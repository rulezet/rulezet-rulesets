rule Win_Trojan_Virut_405
{
strings:
	$a0 = { fce82800000053b9a50d00008bda6631108d400286d68d1413e2f35bc3 }


condition:
	$a0
}