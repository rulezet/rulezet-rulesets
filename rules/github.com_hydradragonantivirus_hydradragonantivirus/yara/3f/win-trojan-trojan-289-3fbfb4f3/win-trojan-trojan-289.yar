rule Win_Trojan_Trojan_289
{
strings:
	$a0 = { 940383c4085633c050b8320050b8040050e8820383c4085e5dc3c3558beceb0a8b1e9e01d1e3ff }


condition:
	$a0
}