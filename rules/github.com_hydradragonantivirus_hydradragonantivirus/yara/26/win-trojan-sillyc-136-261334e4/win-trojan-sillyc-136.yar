rule Win_Trojan_SillyC_136
{
strings:
	$a0 = { b9f3008a6613cd215f595a83c70d33c08a661ccd21c605e98b441a2d0300894501c64503adb104 }


condition:
	$a0
}