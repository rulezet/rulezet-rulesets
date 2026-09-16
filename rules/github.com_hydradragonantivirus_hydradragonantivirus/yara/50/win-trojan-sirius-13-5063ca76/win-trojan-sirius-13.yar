rule Win_Trojan_Sirius_13
{
strings:
	$a0 = { 0190e800005d8d761a90e80200eb108b96c902b9af02d1e931144646e2fac3 }


condition:
	$a0
}