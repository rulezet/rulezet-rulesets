rule Win_Trojan_Vienna_75
{
strings:
	$a0 = { 9c00008c84020007ba5f009003d6b4 }


condition:
	$a0
}