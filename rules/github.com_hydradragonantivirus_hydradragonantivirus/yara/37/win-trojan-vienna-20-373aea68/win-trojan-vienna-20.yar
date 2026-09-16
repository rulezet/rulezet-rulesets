rule Win_Trojan_Vienna_20
{
strings:
	$a0 = { b4408bfa2bd1b91602cd217303e91e00 }


condition:
	$a0
}