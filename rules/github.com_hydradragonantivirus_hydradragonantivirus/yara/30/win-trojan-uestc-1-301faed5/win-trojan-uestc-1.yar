rule Win_Trojan_Uestc_1
{
strings:
	$a0 = { 3bf775f95ec333f6e8e5ffba0001b97803b440cd21 }


condition:
	$a0
}