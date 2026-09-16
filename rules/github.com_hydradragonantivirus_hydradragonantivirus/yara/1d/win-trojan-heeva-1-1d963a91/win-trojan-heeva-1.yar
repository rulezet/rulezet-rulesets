rule Win_Trojan_Heeva_1
{
strings:
	$a0 = { e8740059e2f9ba640006b840008ec0268916130007b905 }


condition:
	$a0
}