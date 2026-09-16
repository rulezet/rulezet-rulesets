rule Win_Trojan_AT_II_2
{
strings:
	$a0 = { f3a48ed97408508701ab588701ab1fad91075ff3a4ebd9601e0680f44b753db8023dcdb8723693b5a08ed91e07b5fa33ffba0200b43fcdb8ab803d4d741a03c250b80042998bcacdb8b4400e1fb170 }


condition:
	$a0
}