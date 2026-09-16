rule Win_Trojan_Suicidal_4
{
strings:
	$a0 = { f9032e8b86340481c17d033bc174be2d03002e8986 }


condition:
	$a0
}