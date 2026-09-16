rule Win_Trojan_Soldier_6
{
strings:
	$a0 = { cd2074112e8b860d042e89868a01c686590101eb0abf00018db60804a5a5a4b83efdcd }


condition:
	$a0
}