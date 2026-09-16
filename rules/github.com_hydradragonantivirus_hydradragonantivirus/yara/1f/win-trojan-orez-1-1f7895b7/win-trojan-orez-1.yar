rule Win_Trojan_Orez_1
{
strings:
	$a0 = { 5669727573202d204f72655a52617453205b496b785d2028432920 }


condition:
	$a0
}