rule Win_Trojan_Trance_2
{
strings:
	$a0 = { 30bbaddecd213dadde7503e99a0033c08ed88e068600 }


condition:
	$a0
}