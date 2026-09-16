rule Win_Trojan_Small_4580
{
strings:
	$a0 = { e8000000005f33f7b8????????8bc85183c032c3bb }


condition:
	$a0
}