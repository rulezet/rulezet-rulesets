rule Win_Trojan_Peed_267
{
strings:
	$a0 = { 68222535000fa25aeb4e5589e5518b7d14b91027000066abc1c807c1c809aa86c4aa }


condition:
	$a0
}