rule Win_Trojan_Goma_22
{
strings:
	$a0 = { 4c4c9a00001b005589e5b800019acd021b0081ec0001bf00000e57b8200050bf50001e579a00 }


condition:
	$a0
}