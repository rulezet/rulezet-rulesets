rule Win_Trojan_Agent_35064
{
strings:
	$a0 = { b5ffffebe85f5e5b8be55dc300ffffffff0a0000005c72727a68682e6461740000ffffffff0c0000007076632e6b6d69 }


condition:
	$a0
}