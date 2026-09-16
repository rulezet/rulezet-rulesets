rule Win_Trojan_Vienna_69
{
strings:
	$a0 = { b440b9dc02908bd681ea1402cd21721f }


condition:
	$a0
}