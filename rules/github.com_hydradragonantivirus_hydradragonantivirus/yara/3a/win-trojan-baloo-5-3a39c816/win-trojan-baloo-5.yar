rule Win_Trojan_Baloo_5
{
strings:
	$a0 = { cd2172a9c3b41aba00ffcd21c3b44eb9ffffba3a03e8e8ffe8 }


condition:
	$a0
}