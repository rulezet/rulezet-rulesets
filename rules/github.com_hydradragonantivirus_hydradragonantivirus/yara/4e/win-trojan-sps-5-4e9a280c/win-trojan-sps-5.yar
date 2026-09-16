rule Win_Trojan_SPS_5
{
strings:
	$a0 = { be3401eb068b89a7ba603c29c981c9320931d281c2c07620c0301421db83c601e0 }


condition:
	$a0
}