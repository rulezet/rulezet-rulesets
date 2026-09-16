rule Win_Trojan_Kitana_7
{
strings:
	$a0 = { 0399b280cd13b80203381fc747fe55aab70175edc30e1fff0e1304cd12c1e0068ec033ffb179f3 }


condition:
	$a0
}