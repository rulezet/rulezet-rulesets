rule Win_Trojan_QQPass_31
{
strings:
	$a0 = { 68d04c400053e82af3ffff89c668dc4c400053e81df3ffff89c785f6745385ff744f }


condition:
	$a0
}