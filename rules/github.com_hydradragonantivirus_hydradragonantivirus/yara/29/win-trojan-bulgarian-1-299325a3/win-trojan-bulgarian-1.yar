rule Win_Trojan_Bulgarian_1
{
strings:
	$a0 = { 038d54f4b440cd21b43ecd21b44fcd }


condition:
	$a0
}