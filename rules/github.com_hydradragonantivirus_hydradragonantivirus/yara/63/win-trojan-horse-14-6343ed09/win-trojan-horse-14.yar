rule Win_Trojan_Horse_14
{
strings:
	$a0 = { ba8000cd13720de89e00b8010329 }


condition:
	$a0
}