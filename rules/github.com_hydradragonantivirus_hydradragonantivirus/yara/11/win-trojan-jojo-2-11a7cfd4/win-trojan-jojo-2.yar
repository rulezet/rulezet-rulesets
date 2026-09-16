rule Win_Trojan_JoJo_2
{
strings:
	$a0 = { 01eb6db42ccd2180fd13720a }


condition:
	$a0
}