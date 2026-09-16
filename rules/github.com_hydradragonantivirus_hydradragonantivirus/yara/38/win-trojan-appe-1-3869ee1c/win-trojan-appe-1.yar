rule Win_Trojan_Appe_1
{
strings:
	$a0 = { 4700a34700e83c01e83d017303e9ea00e82601b440ba4600b90300cd21e9da00a12000a33600a1 }


condition:
	$a0
}