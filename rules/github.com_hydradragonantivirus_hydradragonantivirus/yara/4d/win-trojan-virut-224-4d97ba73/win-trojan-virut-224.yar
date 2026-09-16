rule Win_Trojan_Virut_224
{
strings:
	$a0 = { fce82800000053b9a50d00008bda6631108d400286d68d1413e2f35bc3????5dc355b80080000033c9eb2a0f31c3 }


condition:
	$a0
}