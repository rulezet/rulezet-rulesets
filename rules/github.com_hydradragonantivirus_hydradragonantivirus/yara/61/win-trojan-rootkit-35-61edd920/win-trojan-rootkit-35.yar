rule Win_Trojan_Rootkit_35
{
strings:
	$a0 = { 745d8bb5ecfeffff6a0dbf440601005933c0f3a674498bb5ecfeffff6a0dbf540601005933c0f3a674358bb5ecfeffff6a0dbf640601005933c0f3a67421 }


condition:
	$a0
}