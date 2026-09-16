rule Win_Trojan_NSD_2
{
strings:
	$a0 = { 33c08ec0be0001bf0002b92c01f3a4e82e00ea1a0200001e072bfe2e8b363802b92c01f3a4582ea33602501f07 }


condition:
	$a0
}