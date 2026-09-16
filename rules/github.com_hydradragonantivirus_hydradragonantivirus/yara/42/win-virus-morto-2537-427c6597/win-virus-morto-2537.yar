rule Win_Virus_Morto_2537
{
strings:
	$a0 = { 60e8000000005883c02d33db8b0c1881c1 }


condition:
	$a0
}