rule Win_Trojan_Stigmata_1
{
strings:
	$a0 = { 8d0390d1e973014e8bfead33c3abe2 }


condition:
	$a0
}