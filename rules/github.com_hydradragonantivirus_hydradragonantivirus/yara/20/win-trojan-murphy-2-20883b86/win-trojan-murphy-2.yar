rule Win_Trojan_Murphy_2
{
strings:
	$a0 = { 582e8b847efc2ea300012e8b8480fc }


condition:
	$a0
}