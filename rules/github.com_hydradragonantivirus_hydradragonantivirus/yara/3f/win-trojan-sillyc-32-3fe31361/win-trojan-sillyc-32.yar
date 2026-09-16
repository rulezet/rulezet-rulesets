rule Win_Trojan_SillyC_32
{
strings:
	$a0 = { d2cd21fec4a30301b4405a817e2bb41a74158bcfcd21b8004233c933d2cd21b440fec68bcfcd21 }


condition:
	$a0
}