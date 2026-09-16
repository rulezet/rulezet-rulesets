rule Win_Trojan_Agent_36156
{
strings:
	$a0 = { e8bc050000e9d7fcffff8bff558bec81ec28030000a3a8524000890da45240008915a05240 }


condition:
	$a0
}