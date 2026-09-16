rule Win_Trojan_K_16
{
strings:
	$a0 = { 01a0fc032ea20101a0fd032ea202011e0633c08bf08e }


condition:
	$a0
}