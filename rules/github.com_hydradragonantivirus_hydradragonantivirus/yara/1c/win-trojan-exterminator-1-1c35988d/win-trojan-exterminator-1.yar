rule Win_Trojan_Exterminator_1
{
strings:
	$a0 = { ebe2b42acd213c017403eb2f90c606 }


condition:
	$a0
}