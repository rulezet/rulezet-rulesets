rule Win_Trojan_Antiy_1
{
strings:
	$a0 = { e800005e9c56fcbf000181c6c803b90300f3a55eb4d0cd2180fcd0755f8cc8488ed8803e00005a75 }


condition:
	$a0
}