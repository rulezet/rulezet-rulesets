rule Win_Trojan_AT_3
{
strings:
	$a0 = { 8c2bc13b44017416b440cdf7b8004233c9cdf7b440 }


condition:
	$a0
}