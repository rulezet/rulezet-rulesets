rule Win_Trojan_VGEN_52
{
strings:
	$a0 = { ed0301e81600eb260000e80f00b440b934018d960001cd21e80100c38b9e0d018db63301b98100311c4646e2fac3 }


condition:
	$a0
}