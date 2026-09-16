rule Win_Spyware_Zbot_1287
{
strings:
	$a0 = { ba????4000ff12a3????4000 }


condition:
	$a0
}