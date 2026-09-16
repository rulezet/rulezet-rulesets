rule Win_Trojan_ATII_1
{
strings:
	$a0 = { 4d56560e0eafb02a438ec060a761b13af3a58edb740c508705ab588705ab293e03041fad91075ff3a4c360fc1e0680f44b753db8023dcdc572369333ffb58c8e }


condition:
	$a0
}