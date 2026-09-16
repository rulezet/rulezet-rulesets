rule Win_Trojan_SillyRC_31
{
strings:
	$a0 = { 10008ed8e800005d81ed0801813e0001b8107447bf840033c08ed81e0510008e45028b1d570e1feb08904c3ac015e9 }


condition:
	$a0
}