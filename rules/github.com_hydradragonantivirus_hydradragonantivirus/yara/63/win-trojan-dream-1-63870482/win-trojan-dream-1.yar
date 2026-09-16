rule Win_Trojan_Dream_1
{
strings:
	$a0 = { 522f720085e27400fcba945984eb78003d5adc7a0087c2bdfa05fa553cde7f0084cb70003d62ca720085d77400 }


condition:
	$a0
}