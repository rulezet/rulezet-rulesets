rule Win_Trojan_Chris_597_1
{
strings:
	$a0 = { 8d960301b95502e8ad00b801573e8b963c033e8b8e40 }


condition:
	$a0
}