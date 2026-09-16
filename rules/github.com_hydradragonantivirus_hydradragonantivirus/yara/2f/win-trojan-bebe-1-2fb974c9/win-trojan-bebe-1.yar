rule Win_Trojan_Bebe_1
{
strings:
	$a0 = { 1c35cd21268b47fe2e3b06ee02743189 }


condition:
	$a0
}