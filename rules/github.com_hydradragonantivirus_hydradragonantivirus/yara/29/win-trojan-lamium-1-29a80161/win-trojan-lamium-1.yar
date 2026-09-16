rule Win_Trojan_Lamium_1
{
strings:
	$a0 = { 7665723d5f3d546974616e69756d2076312e }

	$a1 = { 5c737663686f73742e70696600000000ffffffff }


condition:
	$a0 and $a1
}