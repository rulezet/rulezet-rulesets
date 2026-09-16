rule Win_Trojan_Grither_1
{
strings:
	$a0 = { 3dba1f009003d6cd217303e9a3008b }


condition:
	$a0
}