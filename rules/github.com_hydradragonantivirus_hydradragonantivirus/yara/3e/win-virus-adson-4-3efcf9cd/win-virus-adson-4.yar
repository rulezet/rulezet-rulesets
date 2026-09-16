rule Win_Virus_Adson_4
{
strings:
	$a0 = { 2e4164736f6e }

	$a1 = { 609cbd00c008008db5372040008bfeb9ce000000bb????????ad92ad3bd377125352f7e35b03c383d2005bab92abe2e9eb05ab92abe2e2 }


condition:
	$a0 and $a1
}