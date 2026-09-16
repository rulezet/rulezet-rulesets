rule Win_Trojan_Remember_6
{
strings:
	$a0 = { b42acd2181fa180475??b80091cd103d009174 }


condition:
	$a0
}