rule Win_Trojan_Ravage_1
{
strings:
	$a0 = { 1489451689450ec74510beffb98801b440ba4002cd21b8004233c999cd21b4408bd759cd21 }


condition:
	$a0
}