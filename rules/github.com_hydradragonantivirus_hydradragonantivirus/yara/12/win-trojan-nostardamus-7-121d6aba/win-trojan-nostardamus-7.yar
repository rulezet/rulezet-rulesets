rule Win_Trojan_Nostardamus_7
{
strings:
	$a0 = { b1b10b25e165f96cb0b07ed232acc3b223b565f97ed2234cf93f71abd778b7b2b1b1b1d731efb1b1 }


condition:
	$a0
}