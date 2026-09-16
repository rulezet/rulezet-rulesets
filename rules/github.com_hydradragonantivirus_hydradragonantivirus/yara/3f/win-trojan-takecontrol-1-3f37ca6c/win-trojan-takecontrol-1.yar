rule Win_Trojan_TakeControl_1
{
strings:
	$a0 = { 35159b0569a4be9bff015a25696bde24beda396b0d6b71c61a016b0569a4ff9bff42622d6b }


condition:
	$a0
}