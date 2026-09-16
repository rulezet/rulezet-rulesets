rule Win_Trojan_Medbot_76
{
strings:
	$a0 = { 68188140008d8c2440010000e8f3fcffff506a0b68188140008d8c2444050000e8dffcffff5057ff1508804000 }


condition:
	$a0
}