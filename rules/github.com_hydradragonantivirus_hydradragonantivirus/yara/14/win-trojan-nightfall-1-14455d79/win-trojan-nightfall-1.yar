rule Win_Trojan_NightFall_1
{
strings:
	$a0 = { 0bd83a1c2a84613d25d49da0d71e7dbe1c2f2f8d7d8dc0709685ed8a814024ee747d9531 }


condition:
	$a0
}