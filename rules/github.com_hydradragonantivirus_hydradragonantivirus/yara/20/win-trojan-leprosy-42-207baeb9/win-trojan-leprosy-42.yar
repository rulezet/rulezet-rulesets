rule Win_Trojan_Leprosy_42
{
strings:
	$a0 = { 0350e8ec00593d12007424e85700 }


condition:
	$a0
}