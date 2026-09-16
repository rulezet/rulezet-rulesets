rule Win_Trojan_Zeus_1
{
strings:
	$a0 = { c08ed0bc007c8ed8b96900be547cb81990e87a00f21f4179686d1f816d2280ec598769288ae057d22b9153813793 }


condition:
	$a0
}