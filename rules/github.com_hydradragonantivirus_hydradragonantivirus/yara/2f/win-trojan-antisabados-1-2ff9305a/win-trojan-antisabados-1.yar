rule Win_Trojan_AntiSabados_1
{
strings:
	$a0 = { 582d03002d0001952e8a862e0490b979018db63b0189f7505186c1c0c903c0c1032e8b04d3c8d3c0d3c888c987 }


condition:
	$a0
}