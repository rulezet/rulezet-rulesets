rule Win_Trojan_Plastique4096C_1
{
strings:
	$a0 = { 50eaf00300008cc88ed0bcee0d33c08ed82ea11800 }


condition:
	$a0
}