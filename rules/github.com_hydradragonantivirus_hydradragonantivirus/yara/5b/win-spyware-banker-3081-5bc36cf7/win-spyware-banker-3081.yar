rule Win_Spyware_Banker_3081
{
strings:
	$a0 = { b0457eeee9c81f5806aa9b6c42eaf0ba0e28d6cef6b069fa9c3fda45821cd5a46566cbe67a5bcce535190f7e24bf8a56fc96 }


condition:
	$a0
}