rule Win_Trojan_Vienna_97
{
strings:
	$a0 = { 0300e90101525683c6068bfe8bdeb9ff01ac2c30aae2fa5e5ac3 }


condition:
	$a0
}