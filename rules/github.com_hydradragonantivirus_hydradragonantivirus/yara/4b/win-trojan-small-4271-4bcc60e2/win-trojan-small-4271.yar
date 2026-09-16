rule Win_Trojan_Small_4271
{
strings:
	$a0 = { e803000000589718685a0117d4684320 }


condition:
	$a0
}