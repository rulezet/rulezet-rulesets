rule Win_Trojan_W_30
{
strings:
	$a0 = { 56571e06eb02eb0d8cc88ed82ec70605009090eb14b88616cd2f0bc07402eb3db80a000e5bcd31501fb41aba9b02cd }


condition:
	$a0
}