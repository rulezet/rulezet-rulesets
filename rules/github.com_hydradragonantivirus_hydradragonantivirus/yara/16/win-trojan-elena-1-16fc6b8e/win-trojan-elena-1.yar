rule Win_Trojan_Elena_1
{
strings:
	$a0 = { f7ff4747ab3e8a861d02b9ffffcd269d72123e8b961e023e019613023e8a861d02cd269dfc }


condition:
	$a0
}