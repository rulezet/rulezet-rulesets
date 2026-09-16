rule Win_Trojan_ARCV_28
{
strings:
	$a0 = { 1115b924022e81041a0583c6024975f5cefbe65867e9fffb0401f419f4019a25b31c67f5e7fb5b039a04738f0affb3 }


condition:
	$a0
}