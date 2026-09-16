rule Win_Adware_Toolbar_2
{
strings:
	$a0 = { ac71fcff33c05a5959648910684dde43008d45fce84371fcffc3e9b96afcffebf05e5b595dc30000ffffffff08000000544250532e65786500000000ffffffff07000000504942 }


condition:
	$a0
}