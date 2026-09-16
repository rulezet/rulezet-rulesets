rule Win_Trojan_VFSI_2
{
strings:
	$a0 = { d0350f0005020003c88cd8488ed8b80040cd215a59b80157cd21 }


condition:
	$a0
}