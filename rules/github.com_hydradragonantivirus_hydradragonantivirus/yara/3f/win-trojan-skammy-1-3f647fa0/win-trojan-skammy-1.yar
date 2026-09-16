rule Win_Trojan_Skammy_1
{
strings:
	$a0 = { 0200558e0100020001002005000017020000040000002505 }


condition:
	$a0
}