rule Win_Trojan_Mmir_3
{
strings:
	$a0 = { 0ec74510beffb95c01b440ba4002cd21b8004233c999cd21b4408bd759cd215a59b80157cd21 }


condition:
	$a0
}