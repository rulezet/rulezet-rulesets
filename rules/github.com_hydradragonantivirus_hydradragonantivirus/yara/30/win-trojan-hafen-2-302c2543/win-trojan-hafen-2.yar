rule Win_Trojan_Hafen_2
{
strings:
	$a0 = { 038d940001b440cd218b9c3504b9 }


condition:
	$a0
}