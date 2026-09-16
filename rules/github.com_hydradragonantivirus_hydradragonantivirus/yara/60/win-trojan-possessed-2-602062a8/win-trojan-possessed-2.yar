rule Win_Trojan_Possessed_2
{
strings:
	$a0 = { 4dfda1c906051b02cd21891e4f00 }


condition:
	$a0
}