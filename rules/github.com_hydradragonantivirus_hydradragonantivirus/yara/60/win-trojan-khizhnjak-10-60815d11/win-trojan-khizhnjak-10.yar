rule Win_Trojan_Khizhnjak_10
{
strings:
	$a0 = { fe0c1ea2e6028a36e9028a16e8028a2ee7028a0ee6028b }


condition:
	$a0
}