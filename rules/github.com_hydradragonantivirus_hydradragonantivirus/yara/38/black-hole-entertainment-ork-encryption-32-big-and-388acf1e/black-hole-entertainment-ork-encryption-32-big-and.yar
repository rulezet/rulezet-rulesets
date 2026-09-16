rule Black_Hole_Entertainment_ORK_encryption__32_big_AND_
{
strings:
	$a0 = { 48b18039[0-20]48b18039[0-20]48b18039 }

condition:
	$a0
}