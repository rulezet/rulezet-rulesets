rule Win_Trojan_Mybot_7229
{
strings:
	$a0 = { bfe53fc749fa9db984c6ece14a0f1c0fbf78320efe461d6850b27a4ac222c72b572c43c8431bb9e790902bfc61bcfd232d2f230e7a84f57c49b2088c83051a1563fd49a72fcbf75cb086b4ecd14f }


condition:
	$a0
}