rule Win_Trojan_SSR_2
{
strings:
	$a0 = { 829a9af81b889d9b90b0299cb8a000251ef6a2003d9a9b96f0529a53285a581a9acd9953ba9a8d3e }


condition:
	$a0
}