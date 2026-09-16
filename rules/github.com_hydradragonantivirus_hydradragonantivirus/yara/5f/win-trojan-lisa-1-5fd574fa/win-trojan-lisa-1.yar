rule Win_Trojan_Lisa_1
{
strings:
	$a0 = { 028d960301b440cd21e80300c330002e8b862b018db64001b94d0131044646e2fac3 }


condition:
	$a0
}