rule Win_Trojan_Michael_3
{
strings:
	$a0 = { 13042d0300a31304b106d3e0a3d37d8ec0be007c33ffb90002fcf3a4ff2ed17d33c0cd1333c08e }


condition:
	$a0
}