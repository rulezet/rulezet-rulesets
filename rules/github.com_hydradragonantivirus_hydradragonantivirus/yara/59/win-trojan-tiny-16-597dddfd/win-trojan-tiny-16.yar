rule Win_Trojan_Tiny_16
{
strings:
	$a0 = { b29ecd2193b43f5459ba3c01cd21807c3c2a7412fec45033c9f7e1b442cd218bd659b440cd21b4 }


condition:
	$a0
}