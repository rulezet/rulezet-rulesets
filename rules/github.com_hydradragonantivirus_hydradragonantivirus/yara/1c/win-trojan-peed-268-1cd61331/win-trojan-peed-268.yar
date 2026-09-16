rule Win_Trojan_Peed_268
{
strings:
	$a0 = { 89fb682a25ff005ee8910000005589e5518b7d14b91027000066abc1c807c1c8 }


condition:
	$a0
}