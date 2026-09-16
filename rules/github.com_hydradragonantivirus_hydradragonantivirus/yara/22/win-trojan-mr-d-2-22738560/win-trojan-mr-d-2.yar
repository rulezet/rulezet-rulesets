rule Win_Trojan_Mr_D_2
{
strings:
	$a0 = { 02909033c006eb0290908ec026891e040026890e0c000e07e881ffe931feb4408b1e0200cd63c3 }


condition:
	$a0
}