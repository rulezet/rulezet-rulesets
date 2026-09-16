rule Win_Trojan_Vienna_82
{
strings:
	$a0 = { c18905b4408bfa2bd1b9ed01cd217302eb17b8004233c9 }


condition:
	$a0
}