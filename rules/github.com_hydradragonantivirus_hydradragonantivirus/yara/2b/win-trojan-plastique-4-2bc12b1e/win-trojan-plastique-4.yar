rule Win_Trojan_Plastique_4
{
strings:
	$a0 = { cb3c7434833e400efe7403eb4e90fa }


condition:
	$a0
}