rule Win_Trojan_Agent_35390
{
strings:
	$a0 = { 746d7032203d2063687228617363286d696428 }

	$a1 = { 2c20692c20312929202d203129 }


condition:
	$a0 and $a1
}