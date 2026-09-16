rule Win_Trojan_Ailbone_1
{
strings:
	$a0 = { ffbe007cfa8be68ed7fb8ec7bb007eb80402ba8000b904005653cd13e98001 }


condition:
	$a0
}