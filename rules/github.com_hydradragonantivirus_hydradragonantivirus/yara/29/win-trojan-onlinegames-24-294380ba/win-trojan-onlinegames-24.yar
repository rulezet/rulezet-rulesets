rule Win_Trojan_Onlinegames_24
{
strings:
	$a0 = { 558bec81c4c4feffffe802000b57e8020007350bc07505e902 }

	$a1 = { 53656c6644656c2e626174 }


condition:
	$a0 and $a1
}