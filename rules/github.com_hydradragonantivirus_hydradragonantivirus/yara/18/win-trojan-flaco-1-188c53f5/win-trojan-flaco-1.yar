rule Win_Trojan_Flaco_1
{
strings:
	$a0 = { bb000060b803258d9620000e1fcd218db64500b8aafdf7d091cceb26908dbe28002ec605638dbe32002e802d58 }


condition:
	$a0
}