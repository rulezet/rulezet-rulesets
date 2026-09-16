rule Win_Trojan_Oropax_2
{
strings:
	$a0 = { 0100744cb42acd2181f9c307720a }


condition:
	$a0
}