rule Win_Trojan_NTZ_3
{
strings:
	$a0 = { cd21888e2101b9de008db66f018dbe3502a48a86350232862101888635028d7cff8db63502a4 }


condition:
	$a0
}