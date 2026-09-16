rule Win_Trojan_TaiPan_2
{
strings:
	$a0 = { 03b8ce8bcd213dce8b75170e1f81c6ab01bfab01b90a00fcf3a4061f06b8760050cbb448bb1f00cd2173128cd8 }


condition:
	$a0
}