rule Win_Trojan_Promis_1
{
strings:
	$a0 = { 582b83ff56b3e881cf9f2383c11383d18fb426bb21ccb0df96b1ed3a27bf01ad83c5a7b94d9681e5ae9a80fa2bb40a }


condition:
	$a0
}