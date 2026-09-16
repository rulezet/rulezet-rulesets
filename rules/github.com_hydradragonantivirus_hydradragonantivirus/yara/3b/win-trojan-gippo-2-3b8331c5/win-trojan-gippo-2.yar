rule Win_Trojan_Gippo_2
{
strings:
	$a0 = { 511e060e1f8c06c104833ec3042d740dbf3f00b9eb01 }


condition:
	$a0
}