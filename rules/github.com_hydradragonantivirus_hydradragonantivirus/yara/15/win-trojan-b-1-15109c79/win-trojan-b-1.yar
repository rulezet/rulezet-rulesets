rule Win_Trojan_b_1
{
strings:
	$a0 = { 8cd88986e702488ed8a103003d00197303e9ac010e1f8986ff018b9eb702b44acd21 }


condition:
	$a0
}