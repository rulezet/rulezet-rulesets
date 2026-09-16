rule Win_Trojan_Delf_1556
{
strings:
	$a0 = { 8b45ec508d55e4b8??ee4100e87097feff8b45e45ae8??5ffeff85c07e1b68??df4100ba??ee410033c9a160364700e8??7efeffe9a3080000 }


condition:
	$a0
}