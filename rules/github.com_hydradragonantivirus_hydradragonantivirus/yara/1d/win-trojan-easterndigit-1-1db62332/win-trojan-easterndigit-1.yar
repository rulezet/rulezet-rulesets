rule Win_Trojan_EasternDigit_1
{
strings:
	$a0 = { 7503eb0f903d003d7503eb07909d2eff2e79055550 }


condition:
	$a0
}