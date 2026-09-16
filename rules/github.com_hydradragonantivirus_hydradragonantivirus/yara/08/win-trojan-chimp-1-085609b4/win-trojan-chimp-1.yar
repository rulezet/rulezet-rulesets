rule Win_Trojan_Chimp_1
{
strings:
	$a0 = { 8ec0584050be2d7cac8ad08bfeac32c23bfb7403aaebf6c3 }


condition:
	$a0
}