rule Win_Trojan_Twister_6
{
strings:
	$a0 = { 40b9e503bae504e8840172073de5037502f8c3f9c3b440b9e503ba0001e86e01ebe8b440b91200 }


condition:
	$a0
}