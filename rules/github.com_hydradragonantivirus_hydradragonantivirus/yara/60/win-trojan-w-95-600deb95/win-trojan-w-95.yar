rule Win_Trojan_W_95
{
strings:
	$a0 = { e860e8000000005e8b5e1e53b90b0500008a661d8a0332c488034349e302ebf48d76f7c3 }


condition:
	$a0
}