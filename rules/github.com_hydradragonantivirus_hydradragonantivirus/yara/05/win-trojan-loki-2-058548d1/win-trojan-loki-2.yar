rule Win_Trojan_Loki_2
{
strings:
	$a0 = { b3052ec70603014f43e8750033c933d2b800422e8b1ee605e82900bab205b440b90300e81e00 }


condition:
	$a0
}