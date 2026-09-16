rule Win_Trojan_Small_4453
{
strings:
	$a0 = { 83ceff8d86????400040505068d4fbdf0de85d00000052ff35????40 }


condition:
	$a0
}