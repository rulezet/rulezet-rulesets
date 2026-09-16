rule Win_Trojan_Ascii_61_191_188_40_1
{
strings:
	$a0 = { 36312e3139312e3138382e3430 }


condition:
	$a0
}