rule Win_Trojan_Datalock_4
{
strings:
	$a0 = { 3d004b7506e8a200e96b0080fcbf74 }


condition:
	$a0
}