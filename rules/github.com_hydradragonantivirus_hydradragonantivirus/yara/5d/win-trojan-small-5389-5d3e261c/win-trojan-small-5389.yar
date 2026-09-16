rule Win_Trojan_Small_5389
{
strings:
	$a0 = { e84f000000c3eb6181c5ff??ffff83f5ff01ddeb4a81efdc07000089f8eb5d55 }


condition:
	$a0
}