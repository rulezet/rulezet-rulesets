rule Win_Trojan_Since_1
{
strings:
	$a0 = { 010100558e00000000fffff41400006902000004000000f414 }


condition:
	$a0
}