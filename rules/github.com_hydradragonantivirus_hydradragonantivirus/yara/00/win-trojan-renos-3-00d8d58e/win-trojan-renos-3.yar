rule Win_Trojan_Renos_3
{
strings:
	$a0 = { 433a5c[0-1]25633a5c[0-4]633a5c77696e646f7773[0-10]4f70656e[0-4]2f632064656c[0-18]7767657420332e30 }


condition:
	$a0
}