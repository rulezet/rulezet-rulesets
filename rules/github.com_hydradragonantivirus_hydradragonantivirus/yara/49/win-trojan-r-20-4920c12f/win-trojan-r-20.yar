rule Win_Trojan_R_20
{
strings:
	$a0 = { 8b96ae048db61101b9ce0131144646e2fac3 }


condition:
	$a0
}