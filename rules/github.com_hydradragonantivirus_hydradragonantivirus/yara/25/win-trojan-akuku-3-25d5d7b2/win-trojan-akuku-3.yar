rule Win_Trojan_Akuku_3
{
strings:
	$a0 = { 0103d6b440cd2133c933d232c0b442cd21b90500ba6c }


condition:
	$a0
}