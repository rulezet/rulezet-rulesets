rule Win_Trojan_Barrotes_5
{
strings:
	$a0 = { 2e0144712e807c730175021e06b8feeecd213deefe7503e9dd0006b82135cd212e891c2e8c4402078cc0488ec0 }


condition:
	$a0
}