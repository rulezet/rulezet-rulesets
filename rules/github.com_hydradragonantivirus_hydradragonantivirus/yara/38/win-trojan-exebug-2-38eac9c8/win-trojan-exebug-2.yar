rule Win_Trojan_ExeBug_2
{
strings:
	$a0 = { 064c00a3b67cb8990050fcf3a5cb }


condition:
	$a0
}