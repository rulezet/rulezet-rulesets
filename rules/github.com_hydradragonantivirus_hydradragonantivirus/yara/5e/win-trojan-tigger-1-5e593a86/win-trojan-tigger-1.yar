rule Win_Trojan_Tigger_1
{
strings:
	$a0 = { 9c1d06b9db058d570881c606002eac2e32072e8844ff433bda750383eb08e2ed5ec3 }


condition:
	$a0
}