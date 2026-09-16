rule Win_Trojan_BlackJec_1
{
strings:
	$a0 = { 2acd2180fe097519ba0d02b409cd21b419cd218ad0b405b101b500b600b010cd13b98000be8000bf7ffff3a4b82c028bc82d0001a3fa00030e2a02890e }


condition:
	$a0
}