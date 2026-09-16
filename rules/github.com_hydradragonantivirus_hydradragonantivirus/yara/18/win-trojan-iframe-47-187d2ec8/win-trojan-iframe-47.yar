rule Win_Trojan_Iframe_47
{
strings:
	$a0 = { 696672616d657372633d22687474703a2f2f }

	$a1 = { 2f6c696e6b2e68746d6c22 }

	$a2 = { 646973706c61793a6e6f6e653b223e3c2f69667261 }


condition:
	$a0 and $a1 and $a2
}