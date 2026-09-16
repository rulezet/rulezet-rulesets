rule Win_Trojan_Onkelz_7
{
strings:
	$a0 = { e800005d81ed08018db62801e80400eb1200008b9616018bfeb9ec01ac32c2aae2fac3 }


condition:
	$a0
}