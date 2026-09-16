rule Win_Trojan_Yeke_2
{
strings:
	$a0 = { 0eb97604e800005d81ed9f041f03fdfc078bf7ac04 }


condition:
	$a0
}