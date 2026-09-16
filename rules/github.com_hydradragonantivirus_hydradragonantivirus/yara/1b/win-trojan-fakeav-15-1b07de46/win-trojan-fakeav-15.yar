rule Win_Trojan_Fakeav_15
{
strings:
	$a0 = { e8290000006300000000eb90ea1bf2f1f4cd79ef0000b000000000ab }


condition:
	$a0
}