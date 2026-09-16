rule Win_Trojan_Niemela_1
{
strings:
	$a0 = { fc9c1eb82235cd212e891eb7082e8c }


condition:
	$a0
}