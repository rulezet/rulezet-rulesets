rule Win_Trojan_Ja_2
{
strings:
	$a0 = { 02b92500f3a4b8004087f981e9f201baa306cd21b8004233c933d2cd21b440b90500ba9e06cd }


condition:
	$a0
}