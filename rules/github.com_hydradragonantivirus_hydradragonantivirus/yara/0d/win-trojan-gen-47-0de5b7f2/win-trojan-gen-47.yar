rule Win_Trojan_Gen_47
{
strings:
	$a0 = { 8d165301b82125cd215abbb00201 }


condition:
	$a0
}