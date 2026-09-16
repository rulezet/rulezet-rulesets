rule Win_Trojan_VGEN_150
{
strings:
	$a0 = { b92e02bee02cfc300446e2fbeb2496ed8082839e99889fed9091cde7e3e7cde7e38e8280cd1fb0d92400e6cdf6d8 }


condition:
	$a0
}