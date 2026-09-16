rule Win_Trojan_Obfus_38
{
strings:
	$a0 = { 89d9[0-10]29c1[0-10]31d2[0-20]89c8[0-20]f7f7[0-30]3130[0-20]01f8[0-20]67e9 }


condition:
	$a0
}