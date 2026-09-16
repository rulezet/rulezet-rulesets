rule Win_Trojan_Lasky_1
{
strings:
	$a0 = { 803e0000e97521b8024233c9cd21fec4a32601b440b181cd21b8004233c9cd21b440fec6b181cd21 }


condition:
	$a0
}