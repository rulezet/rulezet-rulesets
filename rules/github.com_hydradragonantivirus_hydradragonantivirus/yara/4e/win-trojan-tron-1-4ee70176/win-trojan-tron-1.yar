rule Win_Trojan_Tron_1
{
strings:
	$a0 = { 180146813c545275f9817c024f4e75f283c604ffe6 }


condition:
	$a0
}