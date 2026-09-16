rule Win_Trojan_Nov_1
{
strings:
	$a0 = { 2acd2180fe0b751280fa11720db419cd21b90800ba0100 }


condition:
	$a0
}