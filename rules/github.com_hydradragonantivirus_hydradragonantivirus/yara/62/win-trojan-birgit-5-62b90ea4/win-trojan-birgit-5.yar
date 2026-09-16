rule Win_Trojan_Birgit_5
{
strings:
	$a0 = { bf0001a5a58d964102b41acd218d96f101b44ecd21725e8d965f02b8023dcd2193b90400 }


condition:
	$a0
}