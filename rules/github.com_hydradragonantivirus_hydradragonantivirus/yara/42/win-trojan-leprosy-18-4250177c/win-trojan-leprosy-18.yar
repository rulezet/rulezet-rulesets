rule Win_Trojan_Leprosy_18
{
strings:
	$a0 = { ff00b44ecd21eb005dc3b44fcd21eb00 }


condition:
	$a0
}