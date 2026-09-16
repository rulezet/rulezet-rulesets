rule Win_Trojan_Vienna_21
{
strings:
	$a0 = { fc8bf283c60abf0001b90300f3a48bf2 }


condition:
	$a0
}