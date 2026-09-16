rule Win_Trojan_W_36
{
strings:
	$a0 = { d2b80042cd21bae402b94000b440cd218b1620038b0e2203b80042cd21ba2403b94000b440cd21 }


condition:
	$a0
}