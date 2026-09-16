rule Win_Trojan_Goomba_1
{
strings:
	$a0 = { e800005d83ed031e060e1f8dbe20008b8ed803310d83c7028d96d8033bfa72f3 }


condition:
	$a0
}