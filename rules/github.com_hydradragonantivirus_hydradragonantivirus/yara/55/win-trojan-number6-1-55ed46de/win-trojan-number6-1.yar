rule Win_Trojan_Number6_1
{
strings:
	$a0 = { fc3d7503eb19903d004b7503eb11905d5c5a595b585e5f }


condition:
	$a0
}