rule Win_Trojan_USSR_21
{
strings:
	$a0 = { 8a0734bb880743e2f7595b53ba }


condition:
	$a0
}