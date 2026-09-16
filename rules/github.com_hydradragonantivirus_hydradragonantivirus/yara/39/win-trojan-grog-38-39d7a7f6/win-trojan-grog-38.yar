rule Win_Trojan_Grog_38
{
strings:
	$a0 = { 023dcd21729393b43f8dbc06018bd7b90400cd21725380 }


condition:
	$a0
}