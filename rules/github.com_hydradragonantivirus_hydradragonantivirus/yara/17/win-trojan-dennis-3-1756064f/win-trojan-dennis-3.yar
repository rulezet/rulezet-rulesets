rule Win_Trojan_Dennis_3
{
strings:
	$a0 = { 33c08ec026803e1904dd745c26c6061904dd8cd8488ed88b16030083ea298916030003c2408ec033ff0e1fbe08 }


condition:
	$a0
}