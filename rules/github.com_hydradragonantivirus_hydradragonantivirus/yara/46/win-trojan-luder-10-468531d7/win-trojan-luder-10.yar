rule Win_Trojan_Luder_10
{
strings:
	$a0 = { 33??6a1059??e2fd6a448b????ec108b[0-128]2e65786500 }


condition:
	$a0
}