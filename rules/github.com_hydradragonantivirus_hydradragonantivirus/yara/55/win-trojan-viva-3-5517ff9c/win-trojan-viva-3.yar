rule Win_Trojan_Viva_3
{
strings:
	$a0 = { 8d96a3033e2ecd2106b821353ecd21899eab038c86ad0307b40232d2e85e02b208e85902b4 }


condition:
	$a0
}