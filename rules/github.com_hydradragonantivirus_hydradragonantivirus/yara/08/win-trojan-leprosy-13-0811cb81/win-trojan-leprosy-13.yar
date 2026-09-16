rule Win_Trojan_Leprosy_13
{
strings:
	$a0 = { 1501b44ecd213d12007403e82200b92700ba1b01b44ecd213d12007403e81000ba2101b43bcd21 }


condition:
	$a0
}