rule Win_Trojan_Hmyr_1
{
strings:
	$a0 = { 80ec98b021cd21895efc8c46feba8100e8ea0073178e46f8b44abbffffcd21b44a81eb }


condition:
	$a0
}