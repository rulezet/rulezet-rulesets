rule Win_Trojan_Eumel_13
{
strings:
	$a0 = { 03e9ba00b8023d31867202ba82facd2193b80242e8bb003de9037c163dfff97c11b80057cd }


condition:
	$a0
}