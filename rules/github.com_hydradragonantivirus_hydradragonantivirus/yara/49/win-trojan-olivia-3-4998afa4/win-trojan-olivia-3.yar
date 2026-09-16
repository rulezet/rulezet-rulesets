rule Win_Trojan_Olivia_3
{
strings:
	$a0 = { 8ed8ff360000ff3602006866028f0600008c0e0200 }


condition:
	$a0
}