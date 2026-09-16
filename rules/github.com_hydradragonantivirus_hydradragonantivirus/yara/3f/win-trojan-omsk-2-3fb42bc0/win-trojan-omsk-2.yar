rule Win_Trojan_Omsk_2
{
strings:
	$a0 = { ee03b8feffcd213dfeff7517b90a0081c68c020e1fbf8c02fcf3a4061f06b8760050cbb448bb2b00cd2173128cd8 }


condition:
	$a0
}