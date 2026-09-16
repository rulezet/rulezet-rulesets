rule Win_Trojan_Hydra_13
{
strings:
	$a0 = { b8003fb9ffffba5601cd210556012ea3 }


condition:
	$a0
}