rule Win_Trojan_CureRus_1
{
strings:
	$a0 = { ffcd218cc039d0742b268b163401268e1e3601b82125cd21268b164001268e1e3601b003cd21b449cd21268e062c }


condition:
	$a0
}