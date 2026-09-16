rule Win_Trojan_K_13
{
strings:
	$a0 = { 01a08e032ea20101a08f032ea202018cc8a33d03b980 }


condition:
	$a0
}