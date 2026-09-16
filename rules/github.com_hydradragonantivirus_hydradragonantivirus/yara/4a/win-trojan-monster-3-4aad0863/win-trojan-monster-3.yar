rule Win_Trojan_Monster_3
{
strings:
	$a0 = { 03cd21b440b94301ba0001cd215a59b80157cd2159e8 }


condition:
	$a0
}