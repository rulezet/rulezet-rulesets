rule Win_Trojan_VGEN_569
{
strings:
	$a0 = { 5d81ed31011e06eb0290e9901e33c08ed8bf8400ff35ff75028cd28bf4fa1e8d9e5f0117bc }


condition:
	$a0
}