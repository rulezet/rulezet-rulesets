rule Win_Trojan_Grog_33
{
strings:
	$a0 = { 722f3d60ea772a33d2e8e100b440b90600e8060047bf6aeaeb125acd217303eb3890ba1800 }


condition:
	$a0
}