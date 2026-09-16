rule Win_Trojan_Vecna_8
{
strings:
	$a0 = { 7c0e1fff0e1304cd12b10ad3c88ec033ff8bf4b90001f3a506b8640050cb2ec606010200ff36 }


condition:
	$a0
}