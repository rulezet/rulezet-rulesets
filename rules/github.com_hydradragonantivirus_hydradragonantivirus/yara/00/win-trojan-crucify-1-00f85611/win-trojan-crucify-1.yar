rule Win_Trojan_Crucify_1
{
strings:
	$a0 = { 0bba0001b040e84900b84200e83b00b040bacf01b90400e838008b0ee00b8b16e20bb85701 }


condition:
	$a0
}