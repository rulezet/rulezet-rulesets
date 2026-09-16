rule Win_Trojan_GoldBug_1
{
strings:
	$a0 = { 0102e80d00bbad07e89d00b3ffe89800b4036006bb00808ec3ba800041cdcdb80102cd130761c3 }


condition:
	$a0
}