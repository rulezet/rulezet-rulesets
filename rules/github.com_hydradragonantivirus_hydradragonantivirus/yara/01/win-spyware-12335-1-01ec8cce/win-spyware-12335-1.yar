rule Win_Spyware_12335_1
{
strings:
	$a0 = { 6f6f6f6f6f6f6f0aac6f6fac7e6f6f }


condition:
	$a0
}