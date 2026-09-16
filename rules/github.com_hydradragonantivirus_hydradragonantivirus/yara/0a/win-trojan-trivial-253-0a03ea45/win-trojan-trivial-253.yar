rule Win_Trojan_Trivial_253
{
strings:
	$a0 = { b440b12b9090ba0001cd21b43ecd }


condition:
	$a0
}