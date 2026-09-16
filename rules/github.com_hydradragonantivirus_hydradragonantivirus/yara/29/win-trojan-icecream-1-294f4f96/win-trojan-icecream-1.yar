rule Win_Trojan_Icecream_1
{
strings:
	$a0 = { 50e80000582d130189c58db6f502bf0001a5a4b41aba00f9cd21b44e8d96ef0233c9cd21 }


condition:
	$a0
}