rule Win_Trojan_Striker_2
{
strings:
	$a0 = { c3e96b00b8023dba9e00cd218bd8b800 }


condition:
	$a0
}