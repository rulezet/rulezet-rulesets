rule Win_Trojan_Australian_6
{
strings:
	$a0 = { 820533c08ec0e800005e81ee09000e1ffda7fcb9c600f3a47410bb5800b0482687472cab26875f2e93ab07adad83 }


condition:
	$a0
}