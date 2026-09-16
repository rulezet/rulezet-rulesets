rule Win_Trojan_Turku_1
{
strings:
	$a0 = { 75118cc0bb0001b91000bec005bf00 }


condition:
	$a0
}