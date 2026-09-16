rule Win_Trojan_Procuror_1
{
strings:
	$a0 = { ba8000b90100b80103cd13bb0301ba8000b90800b80103cd13bbe502b90900b80103cd13 }


condition:
	$a0
}