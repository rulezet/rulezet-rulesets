rule Win_Trojan_Hydra_2
{
strings:
	$a0 = { b43db002ba5301b002cd218bd8061fb8003fb9ffffba9301 }


condition:
	$a0
}