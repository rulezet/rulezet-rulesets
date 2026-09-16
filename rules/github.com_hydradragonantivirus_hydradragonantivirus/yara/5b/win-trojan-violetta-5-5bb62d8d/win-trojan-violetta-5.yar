rule Win_Trojan_Violetta_5
{
strings:
	$a0 = { ff061f89dacd210e1fb425b021ba0003cdff }


condition:
	$a0
}