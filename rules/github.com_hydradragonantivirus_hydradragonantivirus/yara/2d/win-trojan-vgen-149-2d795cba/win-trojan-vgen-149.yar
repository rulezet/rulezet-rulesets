rule Win_Trojan_VGEN_149
{
strings:
	$a0 = { 2e02bede2cfc300446e2fb26e996ed8082839e99889fed9091cde7e3e7cde7e38e8280cd1fb0e72400e6cdf6e6 }


condition:
	$a0
}