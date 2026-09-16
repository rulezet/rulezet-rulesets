rule Win_Trojan_Shell_55
{
strings:
	$a0 = { 736d616c6c2070687020776562207368656c6c206279207a61636f }


condition:
	$a0
}