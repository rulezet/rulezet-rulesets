rule Win_Trojan_WWT_2
{
strings:
	$a0 = { 3dcd2172e48bd8b80057cd21891677 }


condition:
	$a0
}