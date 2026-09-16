rule Win_Trojan_Rift_1
{
strings:
	$a0 = { 357d4c00fbcd1248a31304b106d3e08ec08bf4561e50683201fcb90002f3a4cbcd13b8010280 }


condition:
	$a0
}