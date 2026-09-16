rule Win_Trojan_Ocsana_1
{
strings:
	$a0 = { b0d8ba9102bb24012e3007434a83fa01750f2ec7060901e9822ec6060b01010bd275e5 }


condition:
	$a0
}