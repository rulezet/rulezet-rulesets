rule Win_Trojan_TSC_2
{
strings:
	$a0 = { ba0000b90000cd21b440b90400ba900303d6cd21b442b002ba0000b90000cd21b440b9cc0290ba09 }


condition:
	$a0
}