rule Win_Trojan_GR_1
{
strings:
	$a0 = { b96303bb67f1fd3de150bb436090f8902631b7 }


condition:
	$a0
}