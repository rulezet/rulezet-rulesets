rule Win_Trojan_V_4
{
strings:
	$a0 = { 07e800008bfc368b2d81ed0701444450558becc74602054d5d58cd213dffff751dfc8db6f904bf80008bc70580 }


condition:
	$a0
}