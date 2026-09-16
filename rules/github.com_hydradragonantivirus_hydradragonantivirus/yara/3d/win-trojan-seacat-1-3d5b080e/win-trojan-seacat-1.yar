rule Win_Trojan_Seacat_1
{
strings:
	$a0 = { 4d5a74245133c9b80242ccfec42ea3060159b440cc51 }


condition:
	$a0
}