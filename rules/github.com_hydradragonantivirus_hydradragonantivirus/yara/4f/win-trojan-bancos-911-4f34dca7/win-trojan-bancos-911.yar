rule Win_Trojan_Bancos_911
{
strings:
	$a0 = { 2cffa7bb86a98b2b98f2d02876749dfce30bbaf264d711dac92a33bd59cc1b403118db7925ff1ba124fb5967da880e5007116b6b329c29af5b49c084fdc46e497465a55befd687cd5650a4bf6684682d3ad0 }


condition:
	$a0
}