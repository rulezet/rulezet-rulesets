rule Win_Trojan_Trojan_143
{
strings:
	$a0 = { d3e8408cd103c18cd949bf02008ecaba2b008b0d29d13bc8 }


condition:
	$a0
}