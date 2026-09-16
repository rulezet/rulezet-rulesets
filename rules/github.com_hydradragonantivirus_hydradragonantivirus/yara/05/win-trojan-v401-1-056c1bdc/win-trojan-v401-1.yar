rule Win_Trojan_V401_1
{
strings:
	$a0 = { 11ba4b02cd213cff742abe4b02bf95 }


condition:
	$a0
}