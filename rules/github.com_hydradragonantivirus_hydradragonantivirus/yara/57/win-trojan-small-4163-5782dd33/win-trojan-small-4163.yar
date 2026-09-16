rule Win_Trojan_Small_4163
{
strings:
	$a0 = { cd2acd2a29c0e8000000008d }


condition:
	$a0
}