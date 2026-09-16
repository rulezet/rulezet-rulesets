rule Win_Trojan_E_18
{
strings:
	$a0 = { 286329ff4d494b452efa8cc82e01065c008cdabb24008ec333f68ed8b97e00fcf3a5ea290024008edbbe7405813c }


condition:
	$a0
}