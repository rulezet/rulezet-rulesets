rule Win_Trojan_Lokjaw_4
{
strings:
	$a0 = { bb1401b9be008137????817702????83c304e2f2 }


condition:
	$a0
}