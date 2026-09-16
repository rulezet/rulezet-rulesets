rule Win_Trojan_Suicidal_1
{
strings:
	$a0 = { 5d81ed06018db6e403bf000157a5a4ba4559b801facd16b41a8d960604cd21b44732d28db67e04cd212ec606360400 }


condition:
	$a0
}