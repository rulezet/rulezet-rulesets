rule Win_Trojan_Slovakia_12
{
strings:
	$a0 = { b9721cdf0cb175a08485cb82510bb83899c20cd575a0397a596fcd8353fa3441f00f78a738bfb881 }


condition:
	$a0
}