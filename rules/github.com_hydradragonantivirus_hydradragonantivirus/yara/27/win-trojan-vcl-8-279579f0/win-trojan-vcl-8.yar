rule Win_Trojan_VCL_8
{
strings:
	$a0 = { e84500b80242e82500b440b9da008d960301cd21b801575a5980e1c080c901cd21eb0690e8 }


condition:
	$a0
}