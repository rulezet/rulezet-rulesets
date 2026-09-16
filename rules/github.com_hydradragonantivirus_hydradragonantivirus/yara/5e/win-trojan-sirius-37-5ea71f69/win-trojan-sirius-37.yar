rule Win_Trojan_Sirius_37
{
strings:
	$a0 = { 2f59617b92a4d85a617da771de7c93bb142804b5065da7549ecb8e5ede7cab5f13e4195de9c4de7b }


condition:
	$a0
}