rule Win_Trojan_Small_4455
{
strings:
	$a0 = { 8b44241c8d8042858503683255430350 }


condition:
	$a0
}