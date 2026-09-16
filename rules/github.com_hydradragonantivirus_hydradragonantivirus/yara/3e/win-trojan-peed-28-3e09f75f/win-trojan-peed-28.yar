rule Win_Trojan_Peed_28
{
strings:
	$a0 = { fc60c9e15d103a6011d499fd6702c4ab }


condition:
	$a0
}