rule Win_Trojan_Gula_6
{
strings:
	$a0 = { 4233c933d2cd21b440b9c501ba0001cd21b43ecd21ebcdb483cd2181fa99197405ba2101cd27 }


condition:
	$a0
}