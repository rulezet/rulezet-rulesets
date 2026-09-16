rule Win_Trojan_Hydra_10
{
strings:
	$a0 = { b43db002ba5301cd218bd8061fb8003fb9ffffba7401cd21 }


condition:
	$a0
}