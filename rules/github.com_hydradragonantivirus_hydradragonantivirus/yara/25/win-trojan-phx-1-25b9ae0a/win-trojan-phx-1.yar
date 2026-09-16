rule Win_Trojan_Phx_1
{
strings:
	$a0 = { fc4b747d3d023d74433d79b974ea80fc4074da80fc4e74 }


condition:
	$a0
}