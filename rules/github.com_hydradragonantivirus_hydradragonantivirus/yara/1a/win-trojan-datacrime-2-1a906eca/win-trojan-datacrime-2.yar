rule Win_Trojan_Datacrime_2
{
strings:
	$a0 = { 8a0732c2d0ca2e880743e2f3 }


condition:
	$a0
}