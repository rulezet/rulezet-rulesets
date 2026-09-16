rule Win_Trojan_Trivial_483
{
strings:
	$a0 = { cd217217ba9e00b8023dcd218bd7b83040cd21b43ecd21b44febe52bc9b618b24fb707b406cd10 }


condition:
	$a0
}