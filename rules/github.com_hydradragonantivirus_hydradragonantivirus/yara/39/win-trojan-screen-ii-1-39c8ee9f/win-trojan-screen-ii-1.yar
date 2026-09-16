rule Win_Trojan_Screen_II_1
{
strings:
	$a0 = { b90000ba8000cd13b8ff03b90000ba8000cd13 }


condition:
	$a0
}