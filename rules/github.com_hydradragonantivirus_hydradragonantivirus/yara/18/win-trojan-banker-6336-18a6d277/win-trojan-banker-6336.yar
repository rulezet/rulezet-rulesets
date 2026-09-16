rule Win_Trojan_Banker_6336
{
strings:
	$a0 = { 5c6361646f6b322e74787400ffffffff0f0000005c496578706c6f726572722e657865 }

	$a1 = { 4c6f6761646f }


condition:
	$a0 and $a1
}