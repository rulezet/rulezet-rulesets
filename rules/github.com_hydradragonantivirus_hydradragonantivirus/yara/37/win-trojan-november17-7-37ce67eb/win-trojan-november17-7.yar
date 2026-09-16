rule Win_Trojan_November17_7
{
strings:
	$a0 = { cb33c08ed80e07bf3604be8400a5a5be6e04a5c7068400b5018c0e8600c6060c02560e1f }


condition:
	$a0
}