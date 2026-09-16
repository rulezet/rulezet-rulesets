rule Win_Trojan_DS_4
{
strings:
	$a0 = { 02beff04b9ff013814754746e2f9b80042cd722d0300a30402b440b9ff01fec6cd723bc1753f }


condition:
	$a0
}