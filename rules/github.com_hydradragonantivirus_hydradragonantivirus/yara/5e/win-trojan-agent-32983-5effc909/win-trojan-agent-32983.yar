rule Win_Trojan_Agent_32983
{
strings:
	$a0 = { 78149f75e17931f36e6513e74b3f73dfcabcde5bdfb48193755fbbdcda1a4f452696ae6165cf7bdc2b4e2ae669c9a709cd55a8e3befcaac61895f966b9149e6ae2ed34e3ca50d6cdd8a93c5448b0 }


condition:
	$a0
}