rule Win_Trojan_Crypt_209
{
strings:
	$a0 = { 558becb87771c71bbb6ba66f9250e800000000582da81a0000b96d1a0000ba211b0000be0010 }


condition:
	$a0
}