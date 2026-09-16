rule Win_Trojan_Apparition_4
{
strings:
	$a0 = { 21cdcd87d1bf0001f3aa5448452041505041524954494f4e00 }


condition:
	$a0
}