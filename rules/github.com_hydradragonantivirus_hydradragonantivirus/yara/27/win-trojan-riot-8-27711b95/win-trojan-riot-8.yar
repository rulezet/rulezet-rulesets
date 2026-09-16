rule Win_Trojan_Riot_8
{
strings:
	$a0 = { 1e0633c08ed88ec0bf4002397d25741a8d76fdb91a01902ef3a4bf5a03be840056a5a55fb8f502ab91ab071f0be47b }


condition:
	$a0
}