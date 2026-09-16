rule Win_Trojan_Daemean_1
{
strings:
	$a0 = { 1e75f9b8ca02394404740539440575ecad9656bf2108 }


condition:
	$a0
}