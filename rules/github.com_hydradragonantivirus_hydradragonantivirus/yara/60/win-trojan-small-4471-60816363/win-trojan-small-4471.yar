rule Win_Trojan_Small_4471
{
strings:
	$a0 = { ff74241c588d8062aa7504506862343504e86400000040508d15e1e8dd0f5250 }


condition:
	$a0
}