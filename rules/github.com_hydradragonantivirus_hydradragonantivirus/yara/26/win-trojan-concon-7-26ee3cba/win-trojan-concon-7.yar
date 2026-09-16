rule Win_Trojan_Concon_7
{
strings:
	$a0 = { 616c6572742827c4e3d6d0c1cba1f9cdf2[0-59]7372633d633a5c636f6e5c636f6e }


condition:
	$a0
}