rule Win_Trojan_VGEN_489
{
strings:
	$a0 = { 4c55cf9c0ee84f000ac07548505306b462cd218ec3263b1e160075358bda8a0750b42fcd21 }


condition:
	$a0
}