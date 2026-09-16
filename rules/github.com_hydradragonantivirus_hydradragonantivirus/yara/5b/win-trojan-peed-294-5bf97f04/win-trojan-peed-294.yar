rule Win_Trojan_Peed_294
{
strings:
	$a0 = { 05d0f3060054e8030000008f0424c1e11183c4087b5f51b9e803000089d781c1 }


condition:
	$a0
}