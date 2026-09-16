rule Win_Trojan_MGTU_1
{
strings:
	$a0 = { eb03e99700ba9e00b002b43dcd218b }


condition:
	$a0
}