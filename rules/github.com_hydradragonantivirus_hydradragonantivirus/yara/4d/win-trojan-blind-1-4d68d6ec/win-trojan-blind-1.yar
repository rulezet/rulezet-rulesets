rule Win_Trojan_Blind_1
{
strings:
	$a0 = { e800005e478a05e80300eb12908bde81c30602b91a002e3007434975f9c3bf00015681c61c02a5a55eb41a8bd681 }


condition:
	$a0
}