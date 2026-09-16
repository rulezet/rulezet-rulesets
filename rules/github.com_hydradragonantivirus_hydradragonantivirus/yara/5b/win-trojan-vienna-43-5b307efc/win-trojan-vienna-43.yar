rule Win_Trojan_Vienna_43
{
strings:
	$a0 = { fe83c71f908bde83c61f90 }


condition:
	$a0
}