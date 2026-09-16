rule Win_Spyware_Banker_2698
{
strings:
	$a0 = { f9373daa552de5dc924a88f5e990fe01e4eae005f47156e7327dceca9727afb7edae818832053170e556f4a31b05a688bb800d46c1b551f4322bb957c376415224f67bddbffca1feaa0729f2cf41 }


condition:
	$a0
}