rule Win_Trojan_OneHalf_17
{
strings:
	$a0 = { cd12d3e0ba80008ec0b90900b8070206cd13b8d30050cb }


condition:
	$a0
}