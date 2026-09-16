rule Win_Spyware_Banker_1371
{
strings:
	$a0 = { 474d2a39f4887db47126b701815fefa421a6efa3a2bef846332591dd7c6b21e74449cdadae23fd4da40f7e78b9b8d3863001a7b57b016302a8f42276d8d4c9d1c9f78c37 }


condition:
	$a0
}