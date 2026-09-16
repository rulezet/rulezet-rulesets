rule Win_Trojan_Hello_2
{
strings:
	$a0 = { 87fe5d87f78d761e90e80200eb108a968c01b96e018bfe }


condition:
	$a0
}