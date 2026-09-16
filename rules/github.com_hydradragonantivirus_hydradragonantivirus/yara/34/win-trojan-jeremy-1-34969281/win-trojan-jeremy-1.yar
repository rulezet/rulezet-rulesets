rule Win_Trojan_Jeremy_1
{
strings:
	$a0 = { 8d964401cd210e07b4098d964701cd21b82425c5969001cd210e1fcd20b003cf4a6572656d79 }


condition:
	$a0
}