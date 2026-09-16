rule Win_Trojan_Kenson_2
{
strings:
	$a0 = { 40ba00018b0d81c1ae00cd21b43ecd218cd08ed88ec050d1eab41acd21bf000157b96ffef3a4cb }


condition:
	$a0
}