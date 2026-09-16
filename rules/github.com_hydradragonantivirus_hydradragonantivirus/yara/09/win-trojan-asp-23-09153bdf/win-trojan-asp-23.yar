rule Win_Trojan_ASP_23
{
strings:
	$a0 = { 22643a5c746573742e61737022 }

	$a1 = { fd633a2fbbf2633a5cb6bcbfc9d2d4[0-181]b6d4b2bbc6f0a3acc4e3 }


condition:
	$a0 and $a1
}