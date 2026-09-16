rule Win_Trojan_Win_40
{
strings:
	$a0 = { ab648923608743fe83ef97585757acd2c034b57920 }


condition:
	$a0
}