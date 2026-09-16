rule Win_Trojan_SillyOC_33
{
strings:
	$a0 = { 4c02ba0001cd21b43ecd21b44febbab409ba8201cd }


condition:
	$a0
}