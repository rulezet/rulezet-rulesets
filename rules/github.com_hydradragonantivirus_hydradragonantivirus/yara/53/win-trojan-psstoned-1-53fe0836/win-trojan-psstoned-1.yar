rule Win_Trojan_PSStoned_1
{
strings:
	$a0 = { 13e81600b80103b90100b600cd13c3 }


condition:
	$a0
}