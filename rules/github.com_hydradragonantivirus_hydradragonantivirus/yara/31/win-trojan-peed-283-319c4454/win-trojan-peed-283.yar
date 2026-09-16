rule Win_Trojan_Peed_283
{
strings:
	$a0 = { e85d00000051b9d007000089d781c1401f000066abc1c809c1c807aa86c4aa50 }


condition:
	$a0
}