rule Win_Trojan_Leprosy_40
{
strings:
	$a0 = { 0100e80300e9e60051bb36018a2f322e0201882f4381fb5e047ef159c3ba0001bbe30153e8e1ff5bb92803b440cd2153 }


condition:
	$a0
}