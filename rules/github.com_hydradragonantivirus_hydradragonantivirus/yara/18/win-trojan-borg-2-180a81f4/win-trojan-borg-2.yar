rule Win_Trojan_Borg_2
{
strings:
	$a0 = { 0901f4b080e621b85346bb0100b90200f3cd2f2ec68640030033d28edaa10600488ed8b9ffff8bf28b0435f3a5 }


condition:
	$a0
}