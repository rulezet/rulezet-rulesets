rule Win_Trojan_Vic_2
{
strings:
	$a0 = { 5e83c6129056425fb90403fcac34c7aae2fa }


condition:
	$a0
}