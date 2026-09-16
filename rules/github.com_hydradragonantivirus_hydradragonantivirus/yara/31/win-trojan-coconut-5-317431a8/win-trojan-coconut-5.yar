rule Win_Trojan_Coconut_5
{
strings:
	$a0 = { 40b903008d96f008cd21b002e81b00b440b9ee078d960301cd21b43ecd21b44feba4ba8000b41a }


condition:
	$a0
}