rule Win_Trojan_Ultra_1
{
strings:
	$a0 = { b80000bb000090900ee80500b90000eb78585b2d0c00bb01008be8b840008ed8be6c008b0c518b4402508b042bc13d02 }


condition:
	$a0
}