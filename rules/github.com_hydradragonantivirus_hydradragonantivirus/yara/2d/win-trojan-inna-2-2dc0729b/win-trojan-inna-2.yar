rule Win_Trojan_Inna_2
{
strings:
	$a0 = { 1e5768f01931c050509aca07b200bf72011e57bfda371e576a0831c050509aca07b200bf72 }


condition:
	$a0
}