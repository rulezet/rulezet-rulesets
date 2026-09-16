rule Win_Trojan_Bootache_4
{
strings:
	$a0 = { 2d0200a31304b106d3e02d60008ec08bf4bf0406b90001f3a5ba7b060652cb33c022d0cd13 }


condition:
	$a0
}