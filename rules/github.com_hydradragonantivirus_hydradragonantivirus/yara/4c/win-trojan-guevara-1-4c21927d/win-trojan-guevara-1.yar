rule Win_Trojan_Guevara_1
{
strings:
	$a0 = { bae400bd5a07cd10bae500bd6a07cd10b8ef03bb00018ec3b90100ba8000cd13b81c25bac105cd21 }


condition:
	$a0
}