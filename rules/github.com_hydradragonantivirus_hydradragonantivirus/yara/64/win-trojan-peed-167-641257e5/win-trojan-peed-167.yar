rule Win_Trojan_Peed_167
{
strings:
	$a0 = { 89c1bb73e41400fc71315589e5870203550803550cc9c2080081e91132ab0068 }


condition:
	$a0
}