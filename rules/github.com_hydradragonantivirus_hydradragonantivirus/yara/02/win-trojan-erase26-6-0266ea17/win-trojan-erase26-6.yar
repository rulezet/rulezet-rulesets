rule Win_Trojan_Erase26_6
{
strings:
	$a0 = { e90000bb1e01b002b97800ba2c01cd25720cb002b97800ba0100cd267200b44ccd21c3 }


condition:
	$a0
}