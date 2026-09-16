rule Win_Trojan_Delf_1554
{
strings:
	$a0 = { 8bc88d45fc5ae808f4ffff8d45fc508b55fcb8444a1413e83ff4ffff8bc833d28b45fce8abf3ffff8d45fcba504a1413e84ef1ffff8bc38b55fce854f0ffff33c05a5959648910 }


condition:
	$a0
}