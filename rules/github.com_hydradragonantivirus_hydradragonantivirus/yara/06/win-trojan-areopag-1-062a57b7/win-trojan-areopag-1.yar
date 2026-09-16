rule Win_Trojan_Areopag_1
{
strings:
	$a0 = { 3edb0095743233c98bd1b80242cd213d60ea77242d0300a3d50033d2b9e001b440cd213bc17211 }


condition:
	$a0
}