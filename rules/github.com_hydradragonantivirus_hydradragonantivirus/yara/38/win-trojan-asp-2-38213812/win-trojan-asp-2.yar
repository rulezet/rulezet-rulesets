rule Win_Trojan_Asp_2
{
strings:
	$a0 = { be00908ec6268b0e009081f980fc7503eb5890fa }


condition:
	$a0
}