rule Win_Trojan_ArchVir_1
{
strings:
	$a0 = { d003fae090f30426c5550caecd404172105ba030698708000053d1820a0a0aebee0b9c013044 }


condition:
	$a0
}