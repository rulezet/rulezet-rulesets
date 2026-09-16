rule Win_Trojan_CrazyImp_4
{
strings:
	$a0 = { 2cb440ba0b01b9a505cc72213bc175 }


condition:
	$a0
}