rule Win_Spyware_Banker_2806
{
strings:
	$a0 = { bfce8661bb07585e6befa3e4332c40d1bda3e1781c144b86378c7355d54a56aedb7e303b5a048f5b4d708a1df6cedb922412a132ecb616fc0cd6b691a46a9f30d673c3ad0958183e0c4d3c396e851f9e }


condition:
	$a0
}