rule Win_Trojan_DelFil_7
{
strings:
	$a0 = { 64656c20633a5c77696e646f77735c2a2e696e69 }


condition:
	$a0
}