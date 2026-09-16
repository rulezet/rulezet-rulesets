rule Win_Trojan_Darth_1
{
strings:
	$a0 = { 4100723396464e26ad3d2e8b75f826ac3c7574233c9f75ee268b34b9ca008d456a26878480002bc72bc189 }


condition:
	$a0
}