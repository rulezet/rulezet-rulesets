rule Win_Dropper_Agent_33673
{
strings:
	$a0 = { a27f257a9c01a04abcabe4c41d1a58f17f48d15297a5690c8ae37a81577b5fdedd893f6102d08a6a9f7db54f669b1e789b97a28efc785cf9f73c6d8b0e5673eb92beab5ed78f7bed3d25a98cd2c0c285 }


condition:
	$a0
}