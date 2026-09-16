rule Win_Trojan_Lamer_1
{
strings:
	$a0 = { 1b8ed1d5b495dc45bc02bfc279d629cae636a687ee37af409ec59e7fb62fa6dc15ac673413b4c020 }


condition:
	$a0
}