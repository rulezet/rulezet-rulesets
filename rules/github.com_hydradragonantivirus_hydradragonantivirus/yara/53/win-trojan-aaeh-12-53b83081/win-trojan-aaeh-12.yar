rule Win_Trojan_AAEH_12
{
strings:
	$a0 = { 2d433030302d657a776f72 }

	$a1 = { 83c41cc745fc0e000000833dccf3400000751c68ccf3400068bc4a4000ff15ec104000c785ecfeffffccf34000eb0ac7 }


condition:
	$a0 and $a1
}