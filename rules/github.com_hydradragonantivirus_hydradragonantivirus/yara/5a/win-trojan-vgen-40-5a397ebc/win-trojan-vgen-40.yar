rule Win_Trojan_VGEN_40
{
strings:
	$a0 = { db0e0e1f07b91004e800005e81c6110089f7ac34b5aae2fa8edb8ec3fbf33575844c57482727878c15b2da0f9b15cb }


condition:
	$a0
}