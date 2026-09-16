rule Win_Trojan_PS_16
{
strings:
	$a0 = { b88eaecd2181fb9ea0743a8cc0488ed8832e }


condition:
	$a0
}