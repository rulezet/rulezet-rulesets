rule Win_Trojan_Trojan_69
{
strings:
	$a0 = { 8106e83dffb414ba5c06e835ffa1810602e080f4a77517833e9b06007510833e9906407309 }


condition:
	$a0
}