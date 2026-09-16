rule Win_Trojan_Fission_1
{
strings:
	$a0 = { 3d003d74283d013d74233d023d741e3d004374193d014374 }


condition:
	$a0
}