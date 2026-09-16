rule Win_Trojan_SeventhSon_3
{
strings:
	$a0 = { 5eb80033cd2152994050cd21b82435cd2153068d94 }


condition:
	$a0
}