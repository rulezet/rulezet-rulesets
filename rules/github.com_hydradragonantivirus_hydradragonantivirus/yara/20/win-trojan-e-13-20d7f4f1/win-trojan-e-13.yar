rule Win_Trojan_E_13
{
strings:
	$a0 = { 80fc0275219c2eff1e0502721826813feb3e751126c7074d5a60b9010133c08d7f40f3aa61cf }


condition:
	$a0
}