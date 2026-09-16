rule Win_Trojan_Vienna_8
{
strings:
	$a0 = { 0300bf0001f3a48bfab430cd213c007503 }


condition:
	$a0
}