rule Win_Trojan_DM_13
{
strings:
	$a0 = { 2401302446e2fb5ec3e80100cf5d0633c08ec0bb0600 }


condition:
	$a0
}