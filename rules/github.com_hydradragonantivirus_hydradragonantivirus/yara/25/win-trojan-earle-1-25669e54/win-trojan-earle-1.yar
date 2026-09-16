rule Win_Trojan_Earle_1
{
strings:
	$a0 = { 1e9600b9970533d29c2eff1e98007302eb653bc174 }


condition:
	$a0
}