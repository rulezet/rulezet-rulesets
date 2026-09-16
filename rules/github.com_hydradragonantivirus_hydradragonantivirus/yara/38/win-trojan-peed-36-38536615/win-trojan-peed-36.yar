rule Win_Trojan_Peed_36
{
strings:
	$a0 = { 89e58d651c5fc1ef??89ec0562450300 }


condition:
	$a0
}