rule Win_Trojan_Andry_2
{
strings:
	$a0 = { 81ed0300501e06b8becacd213d7a017459b448bb350283c30fb104d3ebcd21731b8cd8488ed88b1e0300b83502051f }


condition:
	$a0
}