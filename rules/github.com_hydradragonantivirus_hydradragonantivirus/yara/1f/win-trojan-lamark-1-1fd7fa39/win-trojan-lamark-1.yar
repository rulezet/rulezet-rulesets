rule Win_Trojan_Lamark_1
{
strings:
	$a0 = { 4f02b82125cd21a12f03a32d03bc0001bb7203b104d3eb43b44acd21bb2c008b07a340038e }


condition:
	$a0
}