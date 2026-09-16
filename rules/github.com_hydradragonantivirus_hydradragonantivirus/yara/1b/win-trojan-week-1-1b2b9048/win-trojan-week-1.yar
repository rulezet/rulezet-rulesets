rule Win_Trojan_Week_1
{
strings:
	$a0 = { b85ddfcd163d490c58c3505351b430cd213c03595b58c3 }


condition:
	$a0
}