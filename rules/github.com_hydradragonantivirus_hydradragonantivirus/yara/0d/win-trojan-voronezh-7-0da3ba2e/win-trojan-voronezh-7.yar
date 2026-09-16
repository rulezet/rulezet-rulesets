rule Win_Trojan_Voronezh_7
{
strings:
	$a0 = { 3e89078ec0bf0001be00015b5301de0e }


condition:
	$a0
}