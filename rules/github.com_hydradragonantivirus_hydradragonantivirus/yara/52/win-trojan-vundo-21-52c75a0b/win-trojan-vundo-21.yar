rule Win_Trojan_Vundo_21
{
strings:
	$a0 = { 60e8d91c000062eb }


condition:
	$a0
}