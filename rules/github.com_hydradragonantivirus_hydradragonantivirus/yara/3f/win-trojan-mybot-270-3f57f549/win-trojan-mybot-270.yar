rule Win_Trojan_Mybot_270
{
strings:
	$a0 = { c7c13c8d00bf8b6edce19c3b14073960ee5c33b00302ac6d004b45594c4f475d580ba0e8d25b00ae2dd9b2e3fe207f3af4f6000c }


condition:
	$a0
}