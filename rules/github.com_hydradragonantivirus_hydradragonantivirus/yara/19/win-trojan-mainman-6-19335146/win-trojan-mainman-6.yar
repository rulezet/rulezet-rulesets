rule Win_Trojan_Mainman_6
{
strings:
	$a0 = { b9380001ca81ed0601b90300bf50018db6640283ef5057f3a4b71a8d96ae028ae7cd21c686590200e8b800e8 }


condition:
	$a0
}