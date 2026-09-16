rule Win_Trojan_VGEN_748
{
strings:
	$a0 = { 2135cd21891e59018c065b01ba1801b425cd21b28ecd2780fc4b753b60061ebf5d01578bf20e07acaa0ac075fa26c6 }


condition:
	$a0
}