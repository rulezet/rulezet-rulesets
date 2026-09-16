rule Win_Trojan_Trivial_394
{
strings:
	$a0 = { b4d94f80f4974f81eaa1484ecd214dba56c545b8e026f881f2c8c535e21bcd21f5ba1bbc8bd8f5 }


condition:
	$a0
}