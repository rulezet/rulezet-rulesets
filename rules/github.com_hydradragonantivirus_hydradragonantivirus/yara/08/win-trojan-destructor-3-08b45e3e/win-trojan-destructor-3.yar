rule Win_Trojan_Destructor_3
{
strings:
	$a0 = { fa8b2e010181ed1fffe8 }


condition:
	$a0
}