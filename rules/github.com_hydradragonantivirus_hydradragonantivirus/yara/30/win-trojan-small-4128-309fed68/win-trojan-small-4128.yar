rule Win_Trojan_Small_4128
{
strings:
	$a0 = { 4072656765646974202f73207375702e7265670d0a4065786974 }


condition:
	$a0
}