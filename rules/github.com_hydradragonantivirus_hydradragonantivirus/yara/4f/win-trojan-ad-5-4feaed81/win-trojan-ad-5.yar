rule Win_Trojan_AD_5
{
strings:
	$a0 = { f400908a6613cd215f595a83c70d33c08a661ccd21c605e98b441a2d0300894501c64503adb104 }


condition:
	$a0
}