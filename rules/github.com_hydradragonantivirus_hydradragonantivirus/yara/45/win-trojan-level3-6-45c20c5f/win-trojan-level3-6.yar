rule Win_Trojan_Level3_6
{
strings:
	$a0 = { be00cc248e89b93a4fca04eb0905599446da74fb4407058cd04a25e814a0 }


condition:
	$a0
}