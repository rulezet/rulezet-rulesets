rule Win_Trojan_Duwende_5
{
strings:
	$a0 = { d20cfc7678d2e97fb693fb082028aa8e2c8a764b723944cb00a9f352f030d489efba7f997596775ed67464ef399be19d }


condition:
	$a0
}