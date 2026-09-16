rule Win_Trojan_IceCream_1
{
strings:
	$a0 = { b440ba00fab9f501cd21b80042e81900b4408d96ec02b90300cd21e81200e962ffe80c00b44fe950 }


condition:
	$a0
}