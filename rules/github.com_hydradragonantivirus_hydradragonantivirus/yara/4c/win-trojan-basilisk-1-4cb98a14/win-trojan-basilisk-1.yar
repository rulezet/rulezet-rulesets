rule Win_Trojan_Basilisk_1
{
strings:
	$a0 = { 5e81ee43068bfe57501e060e070e1fb658b94006ac }


condition:
	$a0
}