rule Win_Trojan_Vgen_13
{
strings:
	$a0 = { 45bb0301b500b100b600b280cd137311720feb0d90c606b70101fe06b801eb0f90803eb801287326803eb70109 }


condition:
	$a0
}