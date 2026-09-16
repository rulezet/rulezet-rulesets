rule Win_Trojan_Incarnate_2
{
strings:
	$a0 = { 0100641b69044d41494e642c2d2a69015a6467d6806c000065015a19641a1b }


condition:
	$a0
}