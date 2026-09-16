rule Win_Trojan_Exterminator_4
{
strings:
	$a0 = { b90b11b44ecd217302eb1eba9e00b8023dcd217302eb128bd8e85100ba8000b44fcd217302eb02ebe2b42acd213c017403eb3690c60687010190b002b9 }


condition:
	$a0
}