rule Win_Trojan_DHeart_1
{
strings:
	$a0 = { 3a03b80042cd217214badd028106df020001b906008b1e3a03b440cd218b1e3a03b43ecd2180 }


condition:
	$a0
}