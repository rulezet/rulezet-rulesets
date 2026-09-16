rule Win_Trojan_KillCMOS_7
{
strings:
	$a0 = { b9ffff8bc1e77033c0e771e2f6b409ba1901cd21b80042cd21434d4f5320436c65617265642e240a0d }


condition:
	$a0
}