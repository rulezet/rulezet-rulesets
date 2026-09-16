rule Win_Trojan_Xrce_3
{
strings:
	$a0 = { 83ee03061e0e1fb8debccd213dcdab7511b8dfbccd213c037203e98100b8e0bccd211e33c08ed8a184002e8984c302 }


condition:
	$a0
}