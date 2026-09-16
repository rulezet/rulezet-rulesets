rule Win_Trojan_Onlinegames_19
{
strings:
	$a0 = { 5c7961686f6f5c7061676572 }

	$a1 = { 27636173736927 }

	$a2 = { 4156495241 }

	$a3 = { 617667756172642e657865 }


condition:
	$a0 and $a1 and $a2 and $a3
}