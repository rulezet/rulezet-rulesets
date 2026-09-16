rule Win_Trojan_Angry_2
{
strings:
	$a0 = { e800005d81ed03012ec6869c03031e068cc88ec08ed8fc8db654028dbe4c02a5a5a5a58d965d04b41acd21b82435cd212e899ea2042e8c86a404b4258d966b03 }


condition:
	$a0
}