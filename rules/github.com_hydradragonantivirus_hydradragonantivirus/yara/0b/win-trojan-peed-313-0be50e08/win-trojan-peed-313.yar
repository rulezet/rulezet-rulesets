rule Win_Trojan_Peed_313
{
strings:
	$a0 = { 8d9032f6000057e84e00000068d4b200005981c1d817000081e964c4ffff81c1c4 }


condition:
	$a0
}