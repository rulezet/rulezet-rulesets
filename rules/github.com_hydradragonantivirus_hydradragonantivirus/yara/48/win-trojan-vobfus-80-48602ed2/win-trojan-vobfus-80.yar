rule Win_Trojan_Vobfus_80
{
strings:
	$a0 = { 4783c34e813e16c3f368ed95000000000000010000000d0a526566654769656f }


condition:
	$a0
}