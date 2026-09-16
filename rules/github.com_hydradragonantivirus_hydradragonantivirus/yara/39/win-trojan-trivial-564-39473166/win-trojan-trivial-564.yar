rule Win_Trojan_Trivial_564
{
strings:
	$a0 = { b44e[0-3]b90000[0-4]cd21[0-4]b43d[0-3]b002[0-7]cd21[0-9]b440[0-6]ba0001[0-6]cd21b43e }


condition:
	$a0
}