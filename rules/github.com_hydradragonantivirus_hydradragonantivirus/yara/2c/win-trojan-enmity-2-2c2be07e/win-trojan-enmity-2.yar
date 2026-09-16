rule Win_Trojan_Enmity_2
{
strings:
	$a0 = { 018b960a048db61a018bfeadeb03abeb0433c2ebf9e2f4c3 }


condition:
	$a0
}