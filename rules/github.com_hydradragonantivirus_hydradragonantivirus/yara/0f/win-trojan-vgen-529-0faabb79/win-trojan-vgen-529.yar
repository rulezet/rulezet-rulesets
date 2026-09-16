rule Win_Trojan_VGEN_529
{
strings:
	$a0 = { ba80fdcd210e1fe92401b41aba00fdcd21b44e8d962e0433c9cd217303e90e01b80043ba1efdcd2151b8014333c9 }


condition:
	$a0
}