rule Win_Trojan_Yunk_1
{
strings:
	$a0 = { 62b7ac40eb257351e58d6037d52653b3e0a79b60ac403f8a279f2575d57bdb5b6362b7ac40e11d75 }


condition:
	$a0
}