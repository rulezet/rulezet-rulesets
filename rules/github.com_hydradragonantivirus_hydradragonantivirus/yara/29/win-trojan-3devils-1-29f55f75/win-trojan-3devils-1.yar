rule Win_Trojan_3Devils_1
{
strings:
	$a0 = { e800005e81ee030133c08ed88ed0bc007ca113042d0400a31304b106d3e08ec02e89843301bf0001 }


condition:
	$a0
}