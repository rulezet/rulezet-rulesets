rule Win_Trojan_Proxy_81
{
strings:
	$a0 = { 01840f53cc5a7000600f54ea0fefd48b15f82e4100bf3057960a81d885e47a8eb83c856e4203df75007c00b9857a4727eb00 }


condition:
	$a0
}