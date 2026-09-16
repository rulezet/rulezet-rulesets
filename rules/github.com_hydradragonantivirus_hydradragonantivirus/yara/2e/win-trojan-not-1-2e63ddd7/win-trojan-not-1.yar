rule Win_Trojan_Not_1
{
strings:
	$a0 = { 83ee038bd6568bbc410281c64302fcb90500f3a4fab800008ed83ea186003e8b3e84008ec00e1f8bf281c6b300b910 }


condition:
	$a0
}