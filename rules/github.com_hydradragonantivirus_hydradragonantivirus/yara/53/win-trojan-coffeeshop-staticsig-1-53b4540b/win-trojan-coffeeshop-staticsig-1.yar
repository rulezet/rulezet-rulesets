rule Win_Trojan_Coffeeshop_staticsig_1
{
strings:
	$a0 = { fb24ccaec24944c4861eb4c7cf60de01cd98841f28d9eb3730b45a1b52155417f4c4487b }


condition:
	$a0
}