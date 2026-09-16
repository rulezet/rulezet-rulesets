rule Win_Trojan_Packed_157
{
strings:
	$a0 = { e8a20700008af649536141a5c4d0b486b1cdebdff6f38c9e92d4fa3616791a6312ed200517c7964938 }


condition:
	$a0
}