rule Win_Trojan_YB_2
{
strings:
	$a0 = { 0356fc81c68201bf0001a5a55eba4559b801facd2106e800000780fc01740580fc02754989bc8b0189948d01bd }


condition:
	$a0
}