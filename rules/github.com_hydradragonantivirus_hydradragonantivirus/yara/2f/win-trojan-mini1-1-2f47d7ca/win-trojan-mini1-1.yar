rule Win_Trojan_Mini1_1
{
strings:
	$a0 = { 803e9b010f7203ba1801b409cd21b44ccd2132c0cfe80f00b440ba0001b98c01cd21e80200 }


condition:
	$a0
}