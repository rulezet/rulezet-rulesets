rule Win_Trojan_Trojan_108
{
strings:
	$a0 = { 53bdebfa58595af7dd55be5301b9202032e9ac488bd8ac2c4103c3aa4d7402e2f10bed7405ad }


condition:
	$a0
}