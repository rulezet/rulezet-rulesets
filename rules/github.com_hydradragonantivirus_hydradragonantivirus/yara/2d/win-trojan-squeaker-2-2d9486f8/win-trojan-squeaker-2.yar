rule Win_Trojan_Squeaker_2
{
strings:
	$a0 = { 7503b480cf80fc4b74052eff2e2c005053521e06 }


condition:
	$a0
}