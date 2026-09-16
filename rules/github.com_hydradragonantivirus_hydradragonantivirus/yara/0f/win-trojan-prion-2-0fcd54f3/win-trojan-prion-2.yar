rule Win_Trojan_Prion_2
{
strings:
	$a0 = { e800005d83ed03fa0e178be583e4fefb500e1fb82425 }

	$a1 = { 5b5072696f6e5d205b4461726b6d616e2f3239415d }


condition:
	$a0 and $a1
}