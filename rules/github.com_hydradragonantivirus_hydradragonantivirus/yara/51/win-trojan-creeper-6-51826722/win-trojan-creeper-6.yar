rule Win_Trojan_Creeper_6
{
strings:
	$a0 = { 071fc3cd20502d004b7426583d00077515a18a018bf0 }


condition:
	$a0
}