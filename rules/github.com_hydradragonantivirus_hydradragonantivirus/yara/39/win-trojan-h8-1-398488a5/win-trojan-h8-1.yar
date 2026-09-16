rule Win_Trojan_H8_1
{
strings:
	$a0 = { 04722d3d67fa73282ea36605b440b99804ba9805cc33c999b80042ccb440ba0001b99804cc2e }


condition:
	$a0
}