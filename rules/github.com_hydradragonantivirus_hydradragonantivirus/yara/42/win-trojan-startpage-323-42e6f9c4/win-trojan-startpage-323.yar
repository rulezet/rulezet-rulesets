rule Win_Trojan_Startpage_323
{
strings:
	$a0 = { 7c7d7d7a666f6b3f0a7d72787c7d7d7a666f6b3e0a687474703a2f2f7777772e766964656f6d }


condition:
	$a0
}