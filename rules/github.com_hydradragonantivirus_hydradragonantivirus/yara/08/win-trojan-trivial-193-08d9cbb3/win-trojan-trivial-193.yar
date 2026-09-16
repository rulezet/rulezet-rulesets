rule Win_Trojan_Trivial_193
{
strings:
	$a0 = { 4eba1f01cd217214b43d40ba9e00cd21b74093ba0001b1 }


condition:
	$a0
}