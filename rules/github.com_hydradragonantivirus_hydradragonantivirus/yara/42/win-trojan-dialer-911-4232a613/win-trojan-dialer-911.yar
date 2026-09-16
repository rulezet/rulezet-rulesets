rule Win_Trojan_Dialer_911
{
strings:
	$a0 = { 526970[0-4]726f7661[15-60]6d6f64[2-9]697364 }


condition:
	$a0
}