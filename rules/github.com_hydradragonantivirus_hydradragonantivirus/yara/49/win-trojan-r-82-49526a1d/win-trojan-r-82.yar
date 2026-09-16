rule Win_Trojan_R_82
{
strings:
	$a0 = { 0500e80f00b440b934018d960001cd21e80100c38b9e0d018db63301b98100311c4646e2fac3 }


condition:
	$a0
}