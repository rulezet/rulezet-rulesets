rule Win_Trojan_Small_4263
{
strings:
	$a0 = { 558bec33d28b4508f7750c0bd275058b4508eb0fba000000008b4508f7750c40f7650cc9c20800 }


condition:
	$a0
}