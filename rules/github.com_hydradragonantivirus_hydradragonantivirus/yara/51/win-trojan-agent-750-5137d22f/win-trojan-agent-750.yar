rule Win_Trojan_Agent_750
{
strings:
	$a0 = { debb7134549b6acd5013b8bea8b046c50dbaddb7c08a9562c23247b55d6f4767434f22989b4e45402d2b3a35f4e50c66abeb3b5ddfc4331fffe0f97afea1e7256ab149cf1ddff2a1698e }


condition:
	$a0
}