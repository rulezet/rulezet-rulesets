rule Win_Trojan_Small_4472
{
strings:
	$a0 = { ff74241c588d80??????04506862343504e86400000040508d15??????0f5250 }


condition:
	$a0
}