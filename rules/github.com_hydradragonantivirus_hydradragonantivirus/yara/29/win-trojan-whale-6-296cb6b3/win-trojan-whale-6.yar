rule Win_Trojan_Whale_6
{
strings:
	$a0 = { e80100c3bb61dc5901cb0eb9c4111ffe }


condition:
	$a0
}