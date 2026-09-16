rule Win_Trojan_SillyORCE_2
{
strings:
	$a0 = { 4b7520061e525153b8023dcdff93b965000e1f33d2b440cdffb43ecdff5b595a1f07cfea }


condition:
	$a0
}