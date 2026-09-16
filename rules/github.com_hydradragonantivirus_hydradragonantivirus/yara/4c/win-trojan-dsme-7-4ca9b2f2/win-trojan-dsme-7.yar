rule Win_Trojan_DSME_7
{
strings:
	$a0 = { c2e2f71b2a241cf74d080507f72fe52728bfd7d72f04ebd788dbaabf63a0da98278ffdd727a230bf93ded3dd6397e5de }


condition:
	$a0
}