rule Win_Trojan_Crypt_186
{
strings:
	$a0 = { 558becb8863c43bfbb2165d90150e800000000582da81a0000b96d1a0000ba211b0000be00100000bf }


condition:
	$a0
}