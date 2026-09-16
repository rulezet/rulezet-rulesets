rule Win_Trojan_Satan2_2
{
strings:
	$a0 = { c5008816c600b800428b1692008b0e9400e80801b440b9e30a33d2e8fe007219 }


condition:
	$a0
}