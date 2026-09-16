rule Win_Trojan_HeyHunter_1
{
strings:
	$a0 = { 5e83ee03b4abbf170003feb93f042e282547e2fa }


condition:
	$a0
}