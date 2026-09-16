rule Win_Trojan_USSR_23
{
strings:
	$a0 = { 01b932008a2480f4dd882446e2f6697610fce08888a8de3453dd5115f0dcdd530566dedde356daf05ddde354dad3c266dfdd56daf05ddd54da531d62dddd }


condition:
	$a0
}