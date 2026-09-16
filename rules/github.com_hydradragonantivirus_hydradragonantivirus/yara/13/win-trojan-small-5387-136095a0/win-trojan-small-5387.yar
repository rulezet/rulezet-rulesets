rule Win_Trojan_Small_5387
{
strings:
	$a0 = { 8d0564858503683255430350e8460000 }


condition:
	$a0
}