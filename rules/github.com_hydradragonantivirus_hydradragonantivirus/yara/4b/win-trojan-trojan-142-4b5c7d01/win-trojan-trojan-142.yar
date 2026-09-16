rule Win_Trojan_Trojan_142
{
strings:
	$a0 = { b93607ac5188d1d2c0fec259aae2f4071f58c3 }


condition:
	$a0
}