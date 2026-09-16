rule Win_Trojan_PHB_2
{
strings:
	$a0 = { 969a12b90300cd21b802422bc92bd2cd21b4408d96 }


condition:
	$a0
}