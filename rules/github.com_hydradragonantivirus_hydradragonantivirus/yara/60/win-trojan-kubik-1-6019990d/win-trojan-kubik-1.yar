rule Win_Trojan_Kubik_1
{
strings:
	$a0 = { 0c0350c6060a01ffb8024233c999e8b1002d0300a38f04b43fb99003ba0001fec450e89d00 }


condition:
	$a0
}