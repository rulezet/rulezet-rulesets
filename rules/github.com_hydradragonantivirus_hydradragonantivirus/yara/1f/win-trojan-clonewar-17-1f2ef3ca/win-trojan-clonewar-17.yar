rule Win_Trojan_Clonewar_17
{
strings:
	$a0 = { 01b90000b8003dcd21c3ba2801b90000b43ccd2172578bd8b90401ba0001b440cd21b43ecd21 }


condition:
	$a0
}