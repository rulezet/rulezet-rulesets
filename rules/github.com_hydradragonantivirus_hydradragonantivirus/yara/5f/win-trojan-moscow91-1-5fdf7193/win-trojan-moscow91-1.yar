rule Win_Trojan_Moscow91_1
{
strings:
	$a0 = { 010300550000000000ffff150300001f020000060000007a08 }


condition:
	$a0
}