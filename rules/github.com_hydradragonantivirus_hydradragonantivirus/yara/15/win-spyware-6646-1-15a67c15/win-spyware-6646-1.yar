rule Win_Spyware_6646_1
{
strings:
	$a0 = { f9e89c05000065b4670105c55e81eb02 }


condition:
	$a0
}