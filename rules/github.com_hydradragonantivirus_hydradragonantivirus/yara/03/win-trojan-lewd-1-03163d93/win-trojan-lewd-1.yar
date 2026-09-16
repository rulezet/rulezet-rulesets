rule Win_Trojan_Lewd_1
{
strings:
	$a0 = { 0426a186002ea3c80407589c2eff1ec604eb05900401889fb442b0008b1e07018b0e37018b }


condition:
	$a0
}