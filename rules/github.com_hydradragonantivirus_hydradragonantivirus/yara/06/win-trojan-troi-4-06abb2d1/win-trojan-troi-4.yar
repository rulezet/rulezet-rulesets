rule Win_Trojan_Troi_4
{
strings:
	$a0 = { fccd213ca574282bc08ec08bf5bf0002b94201f3a4061f }


condition:
	$a0
}