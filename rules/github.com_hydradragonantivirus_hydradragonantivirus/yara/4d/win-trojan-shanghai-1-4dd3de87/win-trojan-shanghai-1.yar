rule Win_Trojan_Shanghai_1
{
strings:
	$a0 = { 8000ac0ac0740be809003c2f740f3c0d75f5c3ac3c2074fb3c0974f7c3e8f3ff8a2425dfdf3d4e5575e4f9c33bf075 }


condition:
	$a0
}