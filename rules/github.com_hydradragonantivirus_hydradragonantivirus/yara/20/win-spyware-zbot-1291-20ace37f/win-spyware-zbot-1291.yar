rule Win_Spyware_Zbot_1291
{
strings:
	$a0 = { 5613df03f948c3 }


condition:
	$a0
}