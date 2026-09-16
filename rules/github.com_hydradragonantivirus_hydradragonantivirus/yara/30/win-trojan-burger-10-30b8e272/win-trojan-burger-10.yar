rule Win_Trojan_Burger_10
{
strings:
	$a0 = { cd21b43ecd212e8b1e00e081fb909074 }


condition:
	$a0
}