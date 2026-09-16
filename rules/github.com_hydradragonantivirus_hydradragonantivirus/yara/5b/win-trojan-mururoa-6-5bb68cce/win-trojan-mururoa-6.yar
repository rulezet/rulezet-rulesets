rule Win_Trojan_Mururoa_6
{
strings:
	$a0 = { b800400e1f2e8b1e1203e8d4fec3b43f0e1f2e8b1e1203e8c7fec3b8023de8c0fe2ea31203c3 }


condition:
	$a0
}