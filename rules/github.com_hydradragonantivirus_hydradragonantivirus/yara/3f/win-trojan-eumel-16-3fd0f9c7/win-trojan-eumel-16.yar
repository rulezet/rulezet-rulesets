rule Win_Trojan_Eumel_16
{
strings:
	$a0 = { 7303e9ba00b8023d31868402ba82facd2193b80242e8bb003de9037c163dfff97c11b80057cd }


condition:
	$a0
}