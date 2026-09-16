rule Win_Trojan_Peed_264
{
strings:
	$a0 = { 68222535000f3158eb4c5589e5518b7d14b91027000066abc1c807c1c809aa }


condition:
	$a0
}