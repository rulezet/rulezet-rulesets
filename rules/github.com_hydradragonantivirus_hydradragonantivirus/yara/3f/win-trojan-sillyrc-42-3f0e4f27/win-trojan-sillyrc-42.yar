rule Win_Trojan_SillyRC_42
{
strings:
	$a0 = { 1f0e07e800008bfc368b2d81ed0701444450558becc74602054d5d58cd213dffff751dfc8db63704bf8000 }


condition:
	$a0
}