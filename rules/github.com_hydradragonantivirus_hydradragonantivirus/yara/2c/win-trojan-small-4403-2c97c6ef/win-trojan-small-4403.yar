rule Win_Trojan_Small_4403
{
strings:
	$a0 = { 89c689c381c0008abffff7d850033424 }


condition:
	$a0
}