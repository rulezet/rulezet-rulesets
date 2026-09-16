rule Win_Trojan_DogLasi_1
{
strings:
	$a0 = { e800005b8d0610062bd8c3301446e2fbc38db78f048dbf28 }


condition:
	$a0
}