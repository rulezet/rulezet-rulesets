rule Win_Trojan_Hal_4
{
strings:
	$a0 = { aae4a6db95a28bd7aa2d99a633a28b36a9632d951e2f674ef036126efda28bdb94a28b37411e3af3 }


condition:
	$a0
}