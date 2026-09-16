rule Win_Trojan_Peed_265
{
strings:
	$a0 = { 89f2682225ab005be89b00000068141900005981c11014000081c11419 }


condition:
	$a0
}