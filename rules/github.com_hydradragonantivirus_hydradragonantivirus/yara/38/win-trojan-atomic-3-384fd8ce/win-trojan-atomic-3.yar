rule Win_Trojan_Atomic_3
{
strings:
	$a0 = { 0701b8024233c933d2cd21ba0c01b91f00b440cd21e959005e1f0e07bf2b01b94000f3a40e1f }


condition:
	$a0
}