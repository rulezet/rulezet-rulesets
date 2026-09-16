rule Win_Trojan_VD_2
{
strings:
	$a0 = { 018bf281c619018bfeb90e01fcad33c2abe2fa }


condition:
	$a0
}