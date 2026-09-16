rule Win_Trojan_K_38
{
strings:
	$a0 = { 8ed0bc007ccd12eb0190b106d3e0b900012bc1a33102ba8000b902008ec0bb0000b80502cd13a1310250 }


condition:
	$a0
}