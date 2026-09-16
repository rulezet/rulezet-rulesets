rule Win_Trojan_Peed_273
{
strings:
	$a0 = { f8ba6745ff00fc89ef73188f05adfa8800f7d36845039900ff1522e48a00e83e }


condition:
	$a0
}