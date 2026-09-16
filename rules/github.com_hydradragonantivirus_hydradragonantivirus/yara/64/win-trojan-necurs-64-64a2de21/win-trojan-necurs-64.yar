rule Win_Trojan_Necurs_64
{
strings:
	$a0 = { 723ecc830085830aca130000ffb00017b64f00830082ff3bb6ddffff }


condition:
	$a0
}