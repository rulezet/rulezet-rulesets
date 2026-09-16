rule Win_Trojan_Small_4627
{
strings:
	$a0 = { 60e8000000008b2c2483c40481ed0b104000b9530400008dbd2a1040008bf7ac34??aae2fa }


condition:
	$a0
}