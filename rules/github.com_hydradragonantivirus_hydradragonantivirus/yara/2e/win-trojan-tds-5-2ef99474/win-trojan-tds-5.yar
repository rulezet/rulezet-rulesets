rule Win_Trojan_TDS_5
{
strings:
	$a0 = { 33d0e9b6060000895c24fc8bdc8d9b580000008d9bacffffff8be38b5c }


condition:
	$a0
}