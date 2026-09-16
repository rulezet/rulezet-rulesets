rule Win_Trojan_SFT_1
{
strings:
	$a0 = { 894515b43fba0001b90303fec4cd2126c745150000b43fbaf703b90300fec4cd21268b450d }


condition:
	$a0
}