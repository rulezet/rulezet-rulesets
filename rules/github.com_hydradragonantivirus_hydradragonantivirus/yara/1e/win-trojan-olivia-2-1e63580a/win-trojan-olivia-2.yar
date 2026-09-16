rule Win_Trojan_Olivia_2
{
strings:
	$a0 = { ff360000ff3602006825008f0600008c0e0200 }


condition:
	$a0
}