rule Win_Trojan_Tiny_70
{
strings:
	$a0 = { b90200b43fcd21813d07087443b8024233c933d2cd21 }


condition:
	$a0
}