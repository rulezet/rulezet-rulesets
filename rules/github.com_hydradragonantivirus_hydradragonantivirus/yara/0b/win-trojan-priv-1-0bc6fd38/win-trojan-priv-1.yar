rule Win_Trojan_Priv_1
{
strings:
	$a0 = { 0790b440e8d0ff33dbc606300000e80900fae42124fe }


condition:
	$a0
}