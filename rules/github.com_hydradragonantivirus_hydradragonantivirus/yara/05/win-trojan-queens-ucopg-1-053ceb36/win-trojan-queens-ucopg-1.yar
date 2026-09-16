rule Win_Trojan_Queens_uCopG_1
{
strings:
	$a0 = { 33c08ec0b801022e803e637c007410b90f00ba8000eb11 }


condition:
	$a0
}