rule Win_Trojan_Hafen_3
{
strings:
	$a0 = { 068d940001b440cd218b9c1704b9 }


condition:
	$a0
}