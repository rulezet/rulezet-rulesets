rule Win_Spyware_Banker_4659
{
strings:
	$a0 = { af3e272b2664145c57de609b7a9d04f072ff8778fae3caba1d9a29ff35dc283bed8336e0a816a1d87dc8165da65abee3591aae7a30cd3ffa256a5ff3f330617230adde8d115de8773102 }


condition:
	$a0
}