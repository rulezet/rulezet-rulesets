rule Win_Trojan_Agent_34698
{
strings:
	$a0 = { 558bec83c4f0b8a0520010e868e6ffff33c05568a453001064ff306489206a006a00e81df8ffff6a }


condition:
	$a0
}