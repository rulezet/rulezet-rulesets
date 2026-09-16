rule Win_Spyware_5473_1
{
strings:
	$a0 = { 52505856be6e0d537581ee6d0d537503 }


condition:
	$a0
}