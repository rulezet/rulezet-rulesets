rule Win_Trojan_Snafu_1
{
strings:
	$a0 = { 0e1ffa0e17be007c8be6fbbf4c001e56f9b80102b90e00bb007e0e07e84e008a36747c }


condition:
	$a0
}