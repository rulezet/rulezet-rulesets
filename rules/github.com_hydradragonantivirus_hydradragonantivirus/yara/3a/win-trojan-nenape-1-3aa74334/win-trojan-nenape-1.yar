rule Win_Trojan_Nenape_1
{
strings:
	$a0 = { 2193538d9e00018dbede01b8de00e84c008bfa03f98bda91e842005bb440cd21b43ecd21b8004c }


condition:
	$a0
}