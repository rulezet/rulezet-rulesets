rule Win_Trojan_Peed_232
{
strings:
	$a0 = { b85468000087f77334ff1543680500ff5500405a5589e551 }


condition:
	$a0
}