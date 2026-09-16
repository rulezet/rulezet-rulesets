rule Win_Trojan_RatSoft_2
{
strings:
	$a0 = { 01b900008b1648018b1e4a01b80042cd217239ba1001b935038b1e4a01b440cd217229b900 }


condition:
	$a0
}