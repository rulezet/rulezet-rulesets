rule Win_Trojan_Trivial_61
{
strings:
	$a0 = { 01b411cd210ac07530ba0001b41acd21be8000bf64018bd7b92500f3a4b416cd21b415cd21b410cd21ba8000b41a }


condition:
	$a0
}