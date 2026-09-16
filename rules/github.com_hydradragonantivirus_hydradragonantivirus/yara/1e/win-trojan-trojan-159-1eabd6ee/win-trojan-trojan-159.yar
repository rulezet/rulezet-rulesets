rule Win_Trojan_Trojan_159
{
strings:
	$a0 = { 7415b44eb92700ba8c01cd217215e81d007504b44feb }


condition:
	$a0
}