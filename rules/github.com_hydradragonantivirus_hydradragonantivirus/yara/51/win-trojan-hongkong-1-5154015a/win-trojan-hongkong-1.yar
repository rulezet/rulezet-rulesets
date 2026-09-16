rule Win_Trojan_HongKong_1
{
strings:
	$a0 = { 33c08ed08ed88ec0bc007cfbbe13048bfead2d0400abb106d3e02d10008ec050b80802bb000153b90300ba8000cd13cb }


condition:
	$a0
}