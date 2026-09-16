rule Win_Trojan_B_244
{
strings:
	$a0 = { 31c0[0-1]8ed88ec0[0-1]8ed0bc007cbe007c[0-3]bf0006[0-1]b98000[0-10]fcf366a5[0-1]ea??060000 }


condition:
	$a0
}