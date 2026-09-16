rule Win_Trojan_Packed_47
{
strings:
	$a0 = { 0fcd0fc1daeb01fc0f }


condition:
	$a0
}