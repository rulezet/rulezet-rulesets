rule Win_Trojan_USSR_7
{
strings:
	$a0 = { 07bb15002e8037464381fb3a027cf5 }


condition:
	$a0
}