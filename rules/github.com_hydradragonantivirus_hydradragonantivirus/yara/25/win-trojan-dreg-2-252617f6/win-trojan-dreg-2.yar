rule Win_Trojan_Dreg_2
{
strings:
	$a0 = { d8cc8b166c048ed95f5257c38db60b018bfeb9af00adeb04abe2fac33386730233866d0233 }


condition:
	$a0
}