rule Win_Trojan_Trojan_166
{
strings:
	$a0 = { 063d03b81c25babf02cd21ba3503 }


condition:
	$a0
}