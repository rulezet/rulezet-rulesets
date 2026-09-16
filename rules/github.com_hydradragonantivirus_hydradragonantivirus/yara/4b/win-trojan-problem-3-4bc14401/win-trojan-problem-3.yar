rule Win_Trojan_Problem_3
{
strings:
	$a0 = { 509e8be589460658e803005d9dcf2e8c1664032e89266203 }


condition:
	$a0
}