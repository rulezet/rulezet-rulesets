rule Win_Trojan_Labet_1
{
strings:
	$a0 = { 6a1c50ff35e1b88c67ff1590cf8c678b45e831f6e9dc0c00008b45f4c645ff013b45e80f8405ffffffff254fbe8c67ff1514d08c67408b1549bd8c67508d8580fdffff506a01535659ff25e9bb8c67 }


condition:
	$a0
}