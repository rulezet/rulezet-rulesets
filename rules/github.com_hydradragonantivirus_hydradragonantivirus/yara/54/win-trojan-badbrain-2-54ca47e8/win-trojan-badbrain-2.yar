rule Win_Trojan_BadBrain_2
{
strings:
	$a0 = { 51b96203be38018bfefcad33060301ab49e302ebf5 }


condition:
	$a0
}