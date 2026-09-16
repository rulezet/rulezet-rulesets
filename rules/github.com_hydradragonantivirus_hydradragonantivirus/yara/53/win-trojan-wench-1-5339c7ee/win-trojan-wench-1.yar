rule Win_Trojan_Wench_1
{
strings:
	$a0 = { ed07eb0190eb0190eb0190fdea }


condition:
	$a0
}