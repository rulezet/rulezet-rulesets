rule Win_Trojan_Tiny_105
{
strings:
	$a0 = { b82125cdc31fb80000a301011e071e50558becc7460200015dcb }


condition:
	$a0
}