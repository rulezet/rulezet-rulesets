rule Win_Trojan_VGEN_547
{
strings:
	$a0 = { e85201e84f01e84c01e849011e06b82c2ccd213dff0f7517071fbf500081c7b0008db63305 }


condition:
	$a0
}