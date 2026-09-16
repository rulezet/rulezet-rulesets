rule Win_Trojan_Htsg_2
{
strings:
	$a0 = { 55e8cd07d629c5c597483bcbd15d10a5af6a21ef09c9e291ec003c90a2671b50879604431786f58c368994c0 }


condition:
	$a0
}