rule Win_Trojan_RussianFlag_1
{
strings:
	$a0 = { da8ed2b81a008ec0bb007c8be3be407cbf4000b94801fcf3a4ea61001a00be4c00a556a58e }


condition:
	$a0
}