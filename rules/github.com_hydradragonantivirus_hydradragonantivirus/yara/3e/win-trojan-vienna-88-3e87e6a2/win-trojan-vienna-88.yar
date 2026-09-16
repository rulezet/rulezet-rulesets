rule Win_Trojan_Vienna_88
{
strings:
	$a0 = { a48bf2b82435cd210653b82425bab60003d6cd211e0706 }


condition:
	$a0
}