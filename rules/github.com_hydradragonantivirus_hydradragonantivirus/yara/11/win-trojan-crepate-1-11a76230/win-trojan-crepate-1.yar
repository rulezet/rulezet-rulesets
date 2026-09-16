rule Win_Trojan_Crepate_1
{
strings:
	$a0 = { 5e81ee03012e80bc5108017403e83f07e9e1059ca1004b7577ebb7807c3d49576a006c7426807c3e4b0f213927 }


condition:
	$a0
}