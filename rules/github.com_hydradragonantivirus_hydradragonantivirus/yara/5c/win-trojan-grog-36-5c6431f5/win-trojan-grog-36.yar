rule Win_Trojan_Grog_36
{
strings:
	$a0 = { 3d8d966e03cd219353b82012cd2fb81612268a1dcd2f }


condition:
	$a0
}