rule Win_Trojan_Trojan_270
{
strings:
	$a0 = { 4acd21a12c00898618008b9e0000ffe37e033801860153e800005b8bfe4f1eff57fa2eff57f81f }


condition:
	$a0
}