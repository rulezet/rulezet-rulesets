rule Win_Trojan_Replico_4
{
strings:
	$a0 = { 408d96130359cd217210b002e82900b440b9a6018d960301cd21b801572e8b8eff022e8b960103 }


condition:
	$a0
}