rule Win_Trojan_Energy_1
{
strings:
	$a0 = { bfe900afae743f80fc03741fe80b01b001e81b017229 }


condition:
	$a0
}