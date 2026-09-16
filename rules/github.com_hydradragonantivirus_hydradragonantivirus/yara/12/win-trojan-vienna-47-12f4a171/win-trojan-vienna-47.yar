rule Win_Trojan_Vienna_47
{
strings:
	$a0 = { b981028bd681ea0202cd217303e98d003d81027403e9 }


condition:
	$a0
}