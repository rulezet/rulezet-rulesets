rule Win_Trojan_Eumel_7
{
strings:
	$a0 = { 03e9a800b8023d31866002ba82facd218bd8b80242e8a8003de9037c163dfff97c11b80057 }


condition:
	$a0
}