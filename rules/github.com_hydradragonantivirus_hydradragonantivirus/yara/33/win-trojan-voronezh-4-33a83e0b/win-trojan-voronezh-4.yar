rule Win_Trojan_Voronezh_4
{
strings:
	$a0 = { 80fcab7505b855559dcf3d003d75 }


condition:
	$a0
}