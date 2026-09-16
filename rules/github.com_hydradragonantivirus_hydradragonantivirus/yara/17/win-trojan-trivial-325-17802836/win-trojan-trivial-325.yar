rule Win_Trojan_Trivial_325
{
strings:
	$a0 = { 01b44eb90100cd21721aba9e00b8023dcd2172108bd8e80c00ba8000b44fcd217202ebe6c3ba0001b440b93c00cd21b43ecd21c3 }


condition:
	$a0
}