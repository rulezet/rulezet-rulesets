rule Win_Trojan_QFat_7
{
strings:
	$a0 = { 012ea102002ea3240132c0b90800020446e2fb2e3a061e0174052eff261a01bb0a00ff37ff77 }


condition:
	$a0
}