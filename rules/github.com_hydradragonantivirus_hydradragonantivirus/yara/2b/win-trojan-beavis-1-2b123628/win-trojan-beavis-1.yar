rule Win_Trojan_Beavis_1
{
strings:
	$a0 = { 018da6d7021e06b8d59a33c98ed99cff1e84000e1f3dd49a7502eb41b82135cd21899eaf028c86b102b80043cd }


condition:
	$a0
}