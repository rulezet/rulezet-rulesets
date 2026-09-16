rule Win_Trojan_Trance_3
{
strings:
	$a0 = { 88138db71201b953032e311c83c602e2f80ff83c2337aa8edea92e3115fd106189881d970da3d306cb3797889dcd11 }


condition:
	$a0
}