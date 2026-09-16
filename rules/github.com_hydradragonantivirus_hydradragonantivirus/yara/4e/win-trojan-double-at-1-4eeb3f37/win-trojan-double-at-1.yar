rule Win_Trojan_Double_At_1
{
strings:
	$a0 = { 6563686f202e42415420766972757320274040272076 }


condition:
	$a0
}