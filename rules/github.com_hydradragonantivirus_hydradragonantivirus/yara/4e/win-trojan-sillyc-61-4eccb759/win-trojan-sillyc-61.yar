rule Win_Trojan_SillyC_61
{
strings:
	$a0 = { e988a6a101b440b9a3008d960a01cd21721bb8004233c933d2cd21b440b904008d96a101cd21b4 }


condition:
	$a0
}