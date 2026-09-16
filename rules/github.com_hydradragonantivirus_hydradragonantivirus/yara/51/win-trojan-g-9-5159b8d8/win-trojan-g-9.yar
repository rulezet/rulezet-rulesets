rule Win_Trojan_G_9
{
strings:
	$a0 = { e800005d81ed0300061eb84144cd213d53507456b44abbffffcd2183eb20b44acd217246832e0200 }


condition:
	$a0
}