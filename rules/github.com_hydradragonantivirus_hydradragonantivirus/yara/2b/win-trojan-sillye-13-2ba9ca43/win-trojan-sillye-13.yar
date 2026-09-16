rule Win_Trojan_SillyE_13
{
strings:
	$a0 = { cd21720bb92003ba0000b80040cd218b1e4701b43ecd21b92000b8011acd21ba4002b41acd21 }


condition:
	$a0
}