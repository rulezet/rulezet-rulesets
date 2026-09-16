rule Win_Trojan_Vienna_80
{
strings:
	$a0 = { 1c8c440207ba5f009003d6b41acd21 }


condition:
	$a0
}