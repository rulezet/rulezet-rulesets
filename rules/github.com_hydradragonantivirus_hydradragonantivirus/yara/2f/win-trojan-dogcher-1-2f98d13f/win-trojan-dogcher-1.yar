rule Win_Trojan_Dogcher_1
{
strings:
	$a0 = { c83d0000743db4ffcd1380fcfa742ab80102bb0003b90100ba8000cd13721afcbebe04bfbe02b94200 }


condition:
	$a0
}