rule Win_Trojan_PS_6
{
strings:
	$a0 = { e90300??????beac01bb19002e8107????83c3024e7402ebf3 }


condition:
	$a0
}