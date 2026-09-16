rule Win_Trojan_IVP_13
{
strings:
	$a0 = { 02902e8ab65703902e8a279032e6902e8827904390e2 }


condition:
	$a0
}