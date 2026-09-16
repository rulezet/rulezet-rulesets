rule Win_Trojan_Vgen_81
{
strings:
	$a0 = { 30cd213c017f02cd20be6a01b9950289f7ac3434aae2fab408b280cd13724488166901b40eb203cd217238b80103b9 }


condition:
	$a0
}