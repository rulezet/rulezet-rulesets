rule Win_Trojan_AdClick_4
{
strings:
	$a0 = { 87687474703a2f2f36362e313530dc21bc6d03340739392f642f490bddb61549226d4d630e26e266dd1a6f6c43 }


condition:
	$a0
}