rule Win_Trojan_Kazanir_1
{
strings:
	$a0 = { b440b90003ba0001cd21b801575a59cd21b43ecd21 }


condition:
	$a0
}