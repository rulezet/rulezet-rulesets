rule Win_Trojan_Crusher_1
{
strings:
	$a0 = { 842509ba0600e8aefeb4408d942509b90200cc8b5460e89efeb4408d941909b90500cce8f6fee9 }


condition:
	$a0
}