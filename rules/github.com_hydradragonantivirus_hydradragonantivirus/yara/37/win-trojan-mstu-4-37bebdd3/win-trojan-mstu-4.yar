rule Win_Trojan_MSTU_4
{
strings:
	$a0 = { 1600268b073deb55c35e8bc6b104d3e80e5b83c36403d8 }


condition:
	$a0
}