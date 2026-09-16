rule Win_Trojan_SdBot_2708
{
strings:
	$a0 = { 7574652e696e666f9f687175ffcfb33823666c6d736b65762e6578650b5736feeeb62264ec732011204d65 }


condition:
	$a0
}