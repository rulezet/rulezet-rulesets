rule Win_Trojan_Delf_2196
{
strings:
	$a0 = { 5172c4a94e1b6c677a03d939e40ce36c1a8c06eeb97463e460107bddecb562155621ec280c053bdda21d3cc40c9e129c60f78266111d195c2019 }


condition:
	$a0
}