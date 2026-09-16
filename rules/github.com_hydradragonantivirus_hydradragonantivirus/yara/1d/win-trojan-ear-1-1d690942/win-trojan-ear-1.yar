rule Win_Trojan_Ear_1
{
strings:
	$a0 = { 44142d030550b91a00b002e89000b4408d96a105cd21b8024233c999cd21b42ccd21898e0c01 }


condition:
	$a0
}