rule Win_Trojan_Xvxh_1
{
strings:
	$a0 = { ff2b4c09034c0781e93e01c704e900894c018bd6b90300b440cd2133c933d2b80042cd218bd6 }


condition:
	$a0
}