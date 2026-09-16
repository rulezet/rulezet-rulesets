rule Win_Trojan_Peed_420
{
strings:
	$a0 = { 81efbde5ffff81ff431a00000f848300000081ffd0b000007f7bb95f3433ff48 }


condition:
	$a0
}