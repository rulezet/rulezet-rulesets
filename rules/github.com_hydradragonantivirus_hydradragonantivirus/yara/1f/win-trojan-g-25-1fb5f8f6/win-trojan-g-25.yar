rule Win_Trojan_G_25
{
strings:
	$a0 = { 3d8d961604cd219353b82012cd2feb12470772076f07 }


condition:
	$a0
}