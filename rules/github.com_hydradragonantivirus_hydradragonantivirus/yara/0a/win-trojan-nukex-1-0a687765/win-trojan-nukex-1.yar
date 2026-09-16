rule Win_Trojan_Nukex_1
{
strings:
	$a0 = { 472ad2be5301cd21b43bba0801cd21720db43aba5001cd217303e9980090b40e8a160701cd21b4 }


condition:
	$a0
}