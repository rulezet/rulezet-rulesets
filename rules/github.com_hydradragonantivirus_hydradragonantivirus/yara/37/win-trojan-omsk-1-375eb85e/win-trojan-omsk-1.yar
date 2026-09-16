rule Win_Trojan_Omsk_1
{
strings:
	$a0 = { ee03b8ffffcd213dffff7517b90a0081c661020e1fbf6102fcf3a4061f06b8760050cbb448bb2a00cd2173128cd8 }


condition:
	$a0
}