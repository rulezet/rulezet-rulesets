rule Win_Trojan_TRIV_1
{
strings:
	$a0 = { 020002c4aae2e25925ff3f03c8890e0101b440ba0001b90d00cd21b440ba5a02b94d01cd21 }


condition:
	$a0
}