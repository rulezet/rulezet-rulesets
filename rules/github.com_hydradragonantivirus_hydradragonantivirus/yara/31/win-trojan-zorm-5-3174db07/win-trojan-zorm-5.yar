rule Win_Trojan_Zorm_5
{
strings:
	$a0 = { 33c98ed9be7001b913002d0100bf10048b1dcd110501002bc393b0c302c32e8a2432e02e882446e2f5 }


condition:
	$a0
}