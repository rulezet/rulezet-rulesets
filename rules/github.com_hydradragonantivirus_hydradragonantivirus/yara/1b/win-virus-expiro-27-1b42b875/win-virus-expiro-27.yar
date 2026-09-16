rule Win_Virus_Expiro_27
{
strings:
	$a0 = { 60e8c154020061e9 }


condition:
	$a0
}