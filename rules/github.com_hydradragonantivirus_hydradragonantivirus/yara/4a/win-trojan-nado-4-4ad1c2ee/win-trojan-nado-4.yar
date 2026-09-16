rule Win_Trojan_Nado_4
{
strings:
	$a0 = { 440289165002a35202050000a34a02c7064c020000b440b95a02ba0000cd210e1fb80242e84b }


condition:
	$a0
}