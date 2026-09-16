rule Win_Trojan_Agent_33348
{
strings:
	$a0 = { 418b3ec687c42151d9abf81c0aad73816a66889dd31d9595b58b20acd262d798dfa4ed29dbe8b9a9cdd43abccdbb3583c7ce5b5ad6f8ebb4f93b304435d8b616d7c4b03f897bed8de674edc8af11 }


condition:
	$a0
}