rule Win_Trojan_Cascade_6
{
strings:
	$a0 = { fae800005bb1eb070183bf010100740e8db72101b9340631 }


condition:
	$a0
}