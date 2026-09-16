rule Win_Trojan_Avalanche_3
{
strings:
	$a0 = { 4036249bbb46b4a5024af18945779b3b45d2c9cfb95396bb0e8a779b86bfc9b953 }


condition:
	$a0
}