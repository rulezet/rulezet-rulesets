rule Win_Trojan_Bagoes_1
{
strings:
	$a0 = { 0e4600e814005a59720ae83eff33dbe8080033f658595b1f07c3b80103e81affc380fc00750c }


condition:
	$a0
}