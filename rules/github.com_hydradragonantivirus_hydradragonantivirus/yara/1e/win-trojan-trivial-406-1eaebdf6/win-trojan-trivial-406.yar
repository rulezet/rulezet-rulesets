rule Win_Trojan_Trivial_406
{
strings:
	$a0 = { 40cd215a59b80157cd21b43ecd21b42acd213a367e01751e3a167f017518b005cd16b007cd161e }


condition:
	$a0
}