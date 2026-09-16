rule Win_Trojan_Small_4149
{
strings:
	$a0 = { 29ed81c500????fff7dd5589ef81c7cf06850581ef3800850583c7056affe821 }


condition:
	$a0
}