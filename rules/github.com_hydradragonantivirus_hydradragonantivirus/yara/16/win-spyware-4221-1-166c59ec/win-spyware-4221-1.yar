rule Win_Spyware_4221_1
{
strings:
	$a0 = { e8df806b792d6c61627330df4bc46fed737406142e73796d61 }


condition:
	$a0
}