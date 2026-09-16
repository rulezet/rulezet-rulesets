rule Win_Trojan_VCC_21
{
strings:
	$a0 = { 2591a94c1cb4cdb8cdcfbec7cd1c94cdacc91c90cd1cdecdd6e0c7cfbeffcd1cf8cdd6e018c9bef8cf1cec }


condition:
	$a0
}