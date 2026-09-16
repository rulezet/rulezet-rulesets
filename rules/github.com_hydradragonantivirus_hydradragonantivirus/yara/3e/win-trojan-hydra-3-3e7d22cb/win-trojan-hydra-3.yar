rule Win_Trojan_Hydra_3
{
strings:
	$a0 = { b43db002ba5301b002cd218bd8061fb8003fb9ffffba5701 }


condition:
	$a0
}