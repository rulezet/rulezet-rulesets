rule Win_Trojan_Cryptowall_4
{
strings:
	$a0 = { 558bec51894dfc8b4dfce8????ffff8b450883e00185c0740c8b4dfc51e8????????83c4048b45fc8be55dc20400ff25????4200cccccc }

	$a1 = { 53e8??????ff41565741663908755ee866??ffff8b??0c33c98bd18b0343413ac275f849894df033c08945f88b0f4903 }


condition:
	$a0 and $a1
}