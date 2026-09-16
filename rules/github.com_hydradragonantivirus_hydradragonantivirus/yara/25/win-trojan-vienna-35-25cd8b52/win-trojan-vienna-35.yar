rule Win_Trojan_Vienna_35
{
strings:
	$a0 = { 06b42fcd21891c8c4402 }


condition:
	$a0
}