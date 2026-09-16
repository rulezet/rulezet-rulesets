rule Win_Trojan_DarthVader_11
{
strings:
	$a0 = { e802fd58ba0001035604b9e20390b440cd21bf6205037e048b0d8b5502b001b457cd21b43ecd21 }


condition:
	$a0
}