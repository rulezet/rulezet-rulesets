rule Win_Trojan_Small_4549
{
strings:
	$a0 = { 89c581c5d88b4000beee9f4000adffd001d5e83800000050e82400000055e837000000 }


condition:
	$a0
}