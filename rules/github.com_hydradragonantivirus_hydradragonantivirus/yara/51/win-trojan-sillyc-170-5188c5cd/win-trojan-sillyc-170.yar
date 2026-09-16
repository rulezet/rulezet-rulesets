rule Win_Trojan_SillyC_170
{
strings:
	$a0 = { b92001ba0001cd2172e2b802422bc92bd2cd2172d7b440b91b00ba200203161c02cd21ebc7b4 }


condition:
	$a0
}