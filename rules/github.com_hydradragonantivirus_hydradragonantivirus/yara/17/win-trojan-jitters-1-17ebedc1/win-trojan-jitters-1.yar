rule Win_Trojan_Jitters_1
{
strings:
	$a0 = { ba5a28b9ba02bfbf00d1ca47314d5a317d5a31555ae2f2ea7bf90990031f6780ab2a3391eccdc04db5d8376b01489e7451e3a79aa8ee147dd9fbb6b9da6ec328de2b6c3648 }


condition:
	$a0
}