rule Win_Trojan_Jacov_18
{
strings:
	$a0 = { 8db617018bfeb96301ad7304abe2fac3354b6873f7 }


condition:
	$a0
}