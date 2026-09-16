rule Win_Trojan_Grog_20
{
strings:
	$a0 = { 3dcd213c53742ae96d012121204d49534355474c494f }


condition:
	$a0
}