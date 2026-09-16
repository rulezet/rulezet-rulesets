rule Win_Trojan_Trivial_Banana_1
{
strings:
	$a0 = { 43cd21b44febb7c32042414e414e412c20636f646564 }


condition:
	$a0
}