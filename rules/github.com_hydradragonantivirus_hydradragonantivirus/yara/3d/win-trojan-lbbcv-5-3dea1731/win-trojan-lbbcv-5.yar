rule Win_Trojan_LBBCV_5
{
strings:
	$a0 = { 0900ba2affb41acd21e83e007510e88f00ba48ffc7 }


condition:
	$a0
}