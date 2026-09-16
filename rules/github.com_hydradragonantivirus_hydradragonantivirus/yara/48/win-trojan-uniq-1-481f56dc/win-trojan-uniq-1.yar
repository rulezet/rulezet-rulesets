rule Win_Trojan_Uniq_1
{
strings:
	$a0 = { ed0301e81700eb27900000e80f00b440b935018d960001cd21e80100c38b9e0e018db63401b98100311c4646e2fac3 }


condition:
	$a0
}