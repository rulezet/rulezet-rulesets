rule Win_Trojan_Birgit_4
{
strings:
	$a0 = { b91900a4e2fdbaf201ffd2c353bada01ffd25bb440b9f200ba0001cd2153bada01ffd25bc3 }


condition:
	$a0
}