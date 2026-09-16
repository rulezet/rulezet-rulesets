rule Win_Trojan_Anni_3
{
strings:
	$a0 = { 5d81ed8b018db6ac01e80200eb13b9cd008bfeba2509ad33c2f7d0abf7d2e2f6c3bb1e25098777c8b9db1e320832d424bdc04cb3f317d7a8bfe7f59a09db0a81ac32e225bdc04ca509 }


condition:
	$a0
}