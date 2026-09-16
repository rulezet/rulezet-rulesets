rule Win_Trojan_Peed_49
{
strings:
	$a0 = { 89c189e58b6d1c83ed0583ed0a4809ed75f8bf99 }


condition:
	$a0
}