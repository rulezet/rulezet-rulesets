rule Win_Trojan_ZigZag_2
{
strings:
	$a0 = { 42cd21b000b457cd215152b440b97f00ba0001cd21b0015a59b457cd21b43ecd219dc3 }


condition:
	$a0
}