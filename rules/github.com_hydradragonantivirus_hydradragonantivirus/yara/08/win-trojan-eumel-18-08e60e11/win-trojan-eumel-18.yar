rule Win_Trojan_Eumel_18
{
strings:
	$a0 = { 03e9ce00b8023d31868402ba82facd2193b80242e8cf003de9037c163dfff97c11b80057cd }


condition:
	$a0
}