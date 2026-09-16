rule Win_Trojan_BadBrainsG_1
{
strings:
	$a0 = { 7303be39018bfefcad33060301ab49e302ebf5 }


condition:
	$a0
}