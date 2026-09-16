rule Win_Trojan_Heeva_2
{
strings:
	$a0 = { 8b1e4381cd21bc0213beaa02cd2e508cc88ed88ec0b9 }


condition:
	$a0
}