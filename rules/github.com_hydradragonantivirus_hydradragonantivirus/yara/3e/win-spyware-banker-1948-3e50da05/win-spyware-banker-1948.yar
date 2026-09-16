rule Win_Spyware_Banker_1948
{
strings:
	$a0 = { 8b55f8b88cd24a00e8a977f5ff85c07e0cbab0d24a008bc3e8f9060000 }


condition:
	$a0
}