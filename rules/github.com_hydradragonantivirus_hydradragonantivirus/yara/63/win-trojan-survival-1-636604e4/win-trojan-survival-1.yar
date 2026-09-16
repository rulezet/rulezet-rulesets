rule Win_Trojan_Survival_1
{
strings:
	$a0 = { b015b430cd213bc37561bf0001be????03f5a5a41f075d5f5e5a595b58bd0001ffe5 }


condition:
	$a0
}