rule Win_Trojan_Problem_9
{
strings:
	$a0 = { e589460658e803005d9dcf2e8c1666032e89266403 }


condition:
	$a0
}