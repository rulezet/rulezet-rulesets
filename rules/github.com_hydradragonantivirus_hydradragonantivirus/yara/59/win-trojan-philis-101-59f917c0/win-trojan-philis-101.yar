rule Win_Trojan_Philis_101
{
strings:
	$a0 = { 6081c6ce29000090bb5351000061606061e80000000033de33de53435b570f }


condition:
	$a0
}