rule Win_Trojan_Androm_14
{
strings:
	$a0 = { 433a5c7765667765665c6d73636f6d63746c2e6f6361 }


condition:
	$a0
}