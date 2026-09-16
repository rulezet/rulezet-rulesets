rule Win_Trojan_Birgit_46
{
strings:
	$a0 = { b800cabb4254cd2f3c007402cd20b82435cd21 }


condition:
	$a0
}