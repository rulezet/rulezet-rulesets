rule Win_Trojan_YB_3
{
strings:
	$a0 = { 21b8004233c999cd218b841a012d03008984fd00b904008d94fc00b440cd21b80157 }


condition:
	$a0
}