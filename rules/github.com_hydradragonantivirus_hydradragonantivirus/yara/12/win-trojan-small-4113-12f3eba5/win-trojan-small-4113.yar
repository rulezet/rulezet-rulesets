rule Win_Trojan_Small_4113
{
strings:
	$a0 = { 64a11e000000bd0b????55e832000000cd205081f6235544 }


condition:
	$a0
}