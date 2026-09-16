rule Win_Trojan_Kuto_3
{
strings:
	$a0 = { 6a00e8610000008bd803583c8b9b80000000891de72040 }


condition:
	$a0
}