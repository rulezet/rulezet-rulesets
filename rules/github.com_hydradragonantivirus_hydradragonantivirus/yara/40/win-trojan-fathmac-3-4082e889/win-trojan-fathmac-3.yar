rule Win_Trojan_FathMac_3
{
strings:
	$a0 = { b9cb062d000081e9220189c989c980c50089d2268a0280ec0034202d000088c926880288e446e2e6 }


condition:
	$a0
}