rule Win_Trojan_USSR_19
{
strings:
	$a0 = { 1e53c51f465f078b073dffff75f283 }


condition:
	$a0
}