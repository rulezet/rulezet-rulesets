rule Win_Trojan_Nines_1
{
strings:
	$a0 = { be110003f3b9aa0289f7ac30d8aae2fa }


condition:
	$a0
}