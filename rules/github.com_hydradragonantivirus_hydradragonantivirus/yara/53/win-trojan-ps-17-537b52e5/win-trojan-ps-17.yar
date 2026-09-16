rule Win_Trojan_PS_17
{
strings:
	$a0 = { 1e06b8cae4cd2181fbaa11743a8cc0488ed8812e }


condition:
	$a0
}