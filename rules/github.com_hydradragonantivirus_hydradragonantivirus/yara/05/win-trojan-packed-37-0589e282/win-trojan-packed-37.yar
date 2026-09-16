rule Win_Trojan_Packed_37
{
strings:
	$a0 = { e80000000058e80000000083c4046a000f }


condition:
	$a0
}