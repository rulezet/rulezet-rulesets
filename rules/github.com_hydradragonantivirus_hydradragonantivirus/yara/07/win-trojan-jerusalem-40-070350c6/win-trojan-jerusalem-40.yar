rule Win_Trojan_Jerusalem_40
{
strings:
	$a0 = { cd2180fcfc731480fc08720fb4ecbf0001be70042e8b0e4101cd21fc0606b840008ec026c606130040072e8c06 }


condition:
	$a0
}