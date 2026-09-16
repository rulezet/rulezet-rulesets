rule Win_Trojan_Peed_300
{
strings:
	$a0 = { 8da832f6ac0050e8b000000051b92003000089d781c1f023000066abc1c80790c1c809aa86c4aa50525183c8 }


condition:
	$a0
}