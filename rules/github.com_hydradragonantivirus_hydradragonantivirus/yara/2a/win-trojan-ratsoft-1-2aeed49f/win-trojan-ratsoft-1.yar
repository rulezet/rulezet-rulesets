rule Win_Trojan_RatSoft_1
{
strings:
	$a0 = { 01b900008b1631018b1e3301b80042cd217239ba1001b9f1028b1e3301b440cd217229b900 }


condition:
	$a0
}