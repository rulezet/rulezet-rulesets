rule Win_Trojan_Dunny_1
{
strings:
	$a0 = { 0103b601b103807f15fd7402b10e890e6800e81d007212e87000b8010333dbb9010033d2e80b00 }


condition:
	$a0
}