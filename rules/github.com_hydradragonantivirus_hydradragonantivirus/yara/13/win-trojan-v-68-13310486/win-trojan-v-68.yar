rule Win_Trojan_V_68
{
strings:
	$a0 = { 0101fcad01c68bd65681c63f02fcbf0001b90500f3a4fab800008ed83ea186003e8b3e84008ec00e1f8bf281c6ad00 }


condition:
	$a0
}