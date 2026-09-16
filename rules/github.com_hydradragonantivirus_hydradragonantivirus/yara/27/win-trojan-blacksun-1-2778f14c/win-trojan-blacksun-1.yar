rule Win_Trojan_Blacksun_1
{
strings:
	$a0 = { b408b2e0cd1380c40bb97e012e8a0432c42e880446e2f561c3 }


condition:
	$a0
}