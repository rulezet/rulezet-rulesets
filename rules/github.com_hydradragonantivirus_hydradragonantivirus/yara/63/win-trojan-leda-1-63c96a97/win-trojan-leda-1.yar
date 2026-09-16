rule Win_Trojan_Leda_1
{
strings:
	$a0 = { bd57cd2181fb14bd7422b82135cd21895c678c4469832e }


condition:
	$a0
}