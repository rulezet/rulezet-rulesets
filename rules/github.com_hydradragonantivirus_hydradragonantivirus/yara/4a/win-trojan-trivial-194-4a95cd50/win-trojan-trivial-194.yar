rule Win_Trojan_Trivial_194
{
strings:
	$a0 = { 4eba1f01cd217214b43d40ba9e00cd21b74093ba0001b125cd21b44febe3 }


condition:
	$a0
}