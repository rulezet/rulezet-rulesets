rule Win_Trojan_Lumbko_1
{
strings:
	$a0 = { 2f696d672f736d736d2e706870 }


condition:
	$a0
}