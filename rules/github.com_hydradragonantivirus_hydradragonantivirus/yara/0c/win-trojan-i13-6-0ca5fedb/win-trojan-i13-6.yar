rule Win_Trojan_I13_6
{
strings:
	$a0 = { ba0002b95a01cd21e82600b440b90400ba6702cd21b4 }


condition:
	$a0
}