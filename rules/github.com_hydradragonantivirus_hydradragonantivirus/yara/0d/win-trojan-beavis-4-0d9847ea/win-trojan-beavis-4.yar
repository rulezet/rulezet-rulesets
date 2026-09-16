rule Win_Trojan_Beavis_4
{
strings:
	$a0 = { feb90002f7f183fa00740140a3a3028916a10233d233c9b80042cd21b91c00ba9f02b440cd21 }


condition:
	$a0
}