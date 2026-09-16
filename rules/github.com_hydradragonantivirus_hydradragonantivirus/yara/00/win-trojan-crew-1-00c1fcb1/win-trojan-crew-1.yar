rule Win_Trojan_Crew_1
{
strings:
	$a0 = { 81e904005f5e5681c61c00b800003904770f }


condition:
	$a0
}