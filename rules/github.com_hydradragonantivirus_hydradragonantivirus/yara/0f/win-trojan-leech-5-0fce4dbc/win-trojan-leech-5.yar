rule Win_Trojan_Leech_5
{
strings:
	$a0 = { fa1e078bec8be681c4e4038c }


condition:
	$a0
}