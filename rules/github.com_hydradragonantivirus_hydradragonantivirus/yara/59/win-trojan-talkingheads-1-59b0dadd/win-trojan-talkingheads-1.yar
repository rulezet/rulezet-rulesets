rule Win_Trojan_TalkingHeads_1
{
strings:
	$a0 = { 1abadc020e1fcd21c606b1020090b44eb92000bab202cd21727cbafa02b0c2b43dcd21a3ba028bd8b457b000cd21890eac028916ae028b1eba02b43fb901 }


condition:
	$a0
}