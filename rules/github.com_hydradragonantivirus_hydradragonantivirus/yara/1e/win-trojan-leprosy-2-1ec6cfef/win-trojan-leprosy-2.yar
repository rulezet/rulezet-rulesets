rule Win_Trojan_Leprosy_2
{
strings:
	$a0 = { b941018b163402b440cd21e89500e8d2 }


condition:
	$a0
}