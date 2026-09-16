rule Win_Trojan_Ng_2
{
strings:
	$a0 = { 7c00730ab8f600cd283d6f007518eb056a01e8d8002e803e03014e7403e81b02eb026a01ebadc60607020090e80c02 }


condition:
	$a0
}