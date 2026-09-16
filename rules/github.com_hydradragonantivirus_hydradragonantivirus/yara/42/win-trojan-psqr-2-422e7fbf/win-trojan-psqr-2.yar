rule Win_Trojan_PSQR_2
{
strings:
	$a0 = { fcb80fffcd213d0101743b06b8f135cd }


condition:
	$a0
}