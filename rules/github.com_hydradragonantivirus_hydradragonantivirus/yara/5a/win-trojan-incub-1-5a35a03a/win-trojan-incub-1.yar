rule Win_Trojan_INCUB_1
{
strings:
	$a0 = { 8ed0bc007c1607bb007eb80102b90627ba0001cd13ffe3 }


condition:
	$a0
}