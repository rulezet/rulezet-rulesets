rule Win_Trojan_Bowl_6
{
strings:
	$a0 = { 8db6ad038bfeacf6d0aae2fac3b4098d965902cd21fab80525bb00b88edbba0000cd21b8 }


condition:
	$a0
}