rule Win_Spyware_Zbot_1289
{
strings:
	$a0 = { 51f7d7c3 }


condition:
	$a0
}