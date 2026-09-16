rule Win_Trojan_Gen_195
{
strings:
	$a0 = { 1a00240408c07613b894008cda5250e8a7fbc43e6e5a26c6451802b800e5cd213d01e5745c31f6 }


condition:
	$a0
}