rule Win_Trojan_OnlineGames_36
{
strings:
	$a0 = { 68aac9f32c333c2483c404568d3781f6aac9f32c87fe5ee83a7301005150585900000000000000 }


condition:
	$a0
}