rule Win_Trojan_Vcl_3
{
strings:
	$a0 = { b44eb927008d96????cd217309e9cb00b44fcd21ebf5b80143ba9e0033c9cd21b8023dba9e00cd2193a1????3d00fa775992b8004233c94a4acd21b43f8d96????b90200cd2181be????????743cb8024233c933d2cd21b4408d96????b97901cd21 }


condition:
	$a0
}