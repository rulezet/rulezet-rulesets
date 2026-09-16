rule Win_Trojan_Lmir_83
{
strings:
	$a0 = { ff4a004c656797ee7fdbfe64204f66204d78208c5c738dbf03a0e0d22f1f66effd6b76d21637dee266770cb19b4446d895ff4cff7fe9ff4e45542e4558457d7377 }


condition:
	$a0
}