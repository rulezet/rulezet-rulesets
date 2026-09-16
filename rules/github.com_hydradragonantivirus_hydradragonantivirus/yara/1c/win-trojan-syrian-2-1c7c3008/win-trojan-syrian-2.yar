rule Win_Trojan_Syrian_2
{
strings:
	$a0 = { fc4b7402eb4eb8023dcd2172478bd8505351521e0e1f }


condition:
	$a0
}