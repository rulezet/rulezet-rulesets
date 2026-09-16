rule Win_Trojan_Momibot_7
{
strings:
	$a0 = { 33c04885c633d433ff33f933c581c76bbd26cf33f3bb932cd8d4c1e71281ebbb25d3b1 }


condition:
	$a0
}