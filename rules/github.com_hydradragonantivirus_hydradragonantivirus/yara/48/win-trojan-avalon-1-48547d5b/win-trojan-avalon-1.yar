rule Win_Trojan_Avalon_1
{
strings:
	$a0 = { cd2180fcee740683ee06e80800bf000157c3b003cf06 }


condition:
	$a0
}