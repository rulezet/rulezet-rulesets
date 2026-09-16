rule Win_Trojan_Peed_405
{
strings:
	$a0 = { 558bec81[0-10]535657 }

	$a1 = { 33c06639413874778945d88d45 }


condition:
	$a0 and $a1
}