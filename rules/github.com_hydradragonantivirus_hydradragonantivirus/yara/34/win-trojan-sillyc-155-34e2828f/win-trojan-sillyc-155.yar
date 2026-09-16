rule Win_Trojan_SillyC_155
{
strings:
	$a0 = { a5a5a5b41a8d962102cd21b44e8d96d50133c9cd217203e826008cc88ed88ec0b41aba8000cd21 }


condition:
	$a0
}