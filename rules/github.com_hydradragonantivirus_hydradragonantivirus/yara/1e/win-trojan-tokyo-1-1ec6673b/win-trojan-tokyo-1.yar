rule Win_Trojan_Tokyo_1
{
strings:
	$a0 = { b42fcd218c060600891e04000e078d16 }


condition:
	$a0
}