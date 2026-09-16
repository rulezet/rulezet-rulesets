rule Win_Trojan_Companion_2
{
strings:
	$a0 = { fe56b4565fcd217219b43c5a52b102cd210e1f93b440b96500ba0001cd21b43ecd21 }


condition:
	$a0
}