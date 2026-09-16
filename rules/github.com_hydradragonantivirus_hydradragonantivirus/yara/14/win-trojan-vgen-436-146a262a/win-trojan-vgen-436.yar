rule Win_Trojan_VGEN_436
{
strings:
	$a0 = { bd00018da6d9021e06b8d59a33c98ed99cff1e84000e1f3dd49a7503eb4290b82135cd21899eb1028c86b302b80043 }


condition:
	$a0
}