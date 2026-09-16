rule Win_Trojan_Trivial_196
{
strings:
	$a0 = { cd21b74093ba0001b125cd21b44febe32a2e434f4d }


condition:
	$a0
}