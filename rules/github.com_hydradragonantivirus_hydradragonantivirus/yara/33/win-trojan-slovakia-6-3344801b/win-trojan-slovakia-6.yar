rule Win_Trojan_Slovakia_6
{
strings:
	$a0 = { e474181ebf03008bf70e1f0e07fcb92f06ac32c4aa80c411e2f71fc3 }


condition:
	$a0
}