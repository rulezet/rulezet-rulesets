rule Win_Trojan_Inopem_1
{
strings:
	$a0 = { 40b904008d96da00cd21fe86de00b802422bc999cd21b440b93e018d960600cd21b43ecd21c3 }


condition:
	$a0
}