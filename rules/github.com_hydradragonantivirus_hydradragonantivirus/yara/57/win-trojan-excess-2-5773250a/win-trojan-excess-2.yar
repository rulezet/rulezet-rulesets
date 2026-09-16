rule Win_Trojan_Excess_2
{
strings:
	$a0 = { f4ffc3b442e8eeffc3b4572e8b1e8a0ee8e3ffc3b443baaa0ee8daffc3e4403c0074fa86e0 }


condition:
	$a0
}