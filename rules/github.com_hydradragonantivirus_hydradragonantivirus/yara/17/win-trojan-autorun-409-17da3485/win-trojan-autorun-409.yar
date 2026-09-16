rule Win_Trojan_Autorun_409
{
strings:
	$a0 = { 52f856575053510f83bfffffff8b2502d3d84f8a65dc4f9d }

	$a1 = { 363834393434434230343632 }

	$a2 = { 52656745782e666e72 }


condition:
	$a0 and $a1 and $a2
}