rule Win_Trojan_K_20
{
strings:
	$a0 = { b80042cd217239ba1001b9ed028b1ecc02b440cd217229 }


condition:
	$a0
}