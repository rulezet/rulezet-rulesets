rule Win_Trojan_Witam_1
{
strings:
	$a0 = { 0f028dab0c8abfdd3476f6742a1d1b147aac65f8296904b46818803e530000740c01500752 }


condition:
	$a0
}