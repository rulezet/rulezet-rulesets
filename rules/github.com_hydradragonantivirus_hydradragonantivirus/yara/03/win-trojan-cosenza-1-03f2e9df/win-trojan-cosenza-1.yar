rule Win_Trojan_Cosenza_1
{
strings:
	$a0 = { 87ed72f9d4ff2c008ac48bd8bb2401b99607b6782e303743e2fa }


condition:
	$a0
}