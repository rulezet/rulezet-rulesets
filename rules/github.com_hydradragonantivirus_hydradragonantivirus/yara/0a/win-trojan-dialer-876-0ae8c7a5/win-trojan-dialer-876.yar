rule Win_Trojan_Dialer_876
{
strings:
	$a0 = { 4449414c45525f494e5354414e43455f4d555445585f475549257300 }


condition:
	$a0
}