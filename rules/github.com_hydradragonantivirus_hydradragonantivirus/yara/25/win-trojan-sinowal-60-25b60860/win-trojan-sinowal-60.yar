rule Win_Trojan_Sinowal_60
{
strings:
	$a0 = { 8bc0558bec8b4510508b4d0c518b550852e824f3ffff5dc20c008bc0558bec81 }


condition:
	$a0
}