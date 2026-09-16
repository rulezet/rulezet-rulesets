rule Win_Spyware_4722_1
{
strings:
	$a0 = { 6050812c244242a721586113c1 }


condition:
	$a0
}