rule Win_Trojan_Sistor_1
{
strings:
	$a0 = { ff00891684008c068600fb33c08ed8b84953a340032e80bc }


condition:
	$a0
}