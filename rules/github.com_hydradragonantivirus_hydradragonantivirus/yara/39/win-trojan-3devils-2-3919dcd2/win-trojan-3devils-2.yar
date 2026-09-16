rule Win_Trojan_3Devils_2
{
strings:
	$a0 = { 890eb301b801039c2eff1ebb017216b801035a52b600b901000e078d1e00019c2eff1ebb01 }


condition:
	$a0
}