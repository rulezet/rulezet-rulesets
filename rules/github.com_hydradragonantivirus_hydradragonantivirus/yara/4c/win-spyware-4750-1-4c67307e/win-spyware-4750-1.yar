rule Win_Spyware_4750_1
{
strings:
	$a0 = { 6051b95040ba2c81c16ecabdde03f959 }


condition:
	$a0
}