rule Win_Trojan_Vundo_20
{
strings:
	$a0 = { 60e882090000d0c9 }


condition:
	$a0
}