rule Win_Trojan_Polimer_2
{
strings:
	$a0 = { 0500108ed8b440cd218cd82d0010 }


condition:
	$a0
}