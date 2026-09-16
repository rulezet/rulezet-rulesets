rule Win_Trojan_Lyceum_7
{
strings:
	$a0 = { e800005e83ee??2ec684??????fc5053b8ccabcd213d93197505 }


condition:
	$a0
}