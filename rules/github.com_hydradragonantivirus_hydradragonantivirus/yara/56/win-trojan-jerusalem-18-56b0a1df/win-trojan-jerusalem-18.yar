rule Win_Trojan_Jerusalem_18
{
strings:
	$a0 = { 01b970042e8a2530d430f430cc2e882547e2f1c3eaac1750c9e81a00e8dcff31d2b968 }


condition:
	$a0
}