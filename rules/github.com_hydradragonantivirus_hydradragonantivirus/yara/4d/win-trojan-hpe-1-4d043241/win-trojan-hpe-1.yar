rule Win_Trojan_HPE_1
{
strings:
	$a0 = { 945df79cb09e9429f7b3394e0ba2b281730952a706ee086cbb7f93903bdba7bce5b4b500b2bf0d0c }


condition:
	$a0
}