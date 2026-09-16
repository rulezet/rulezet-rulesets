rule Win_Trojan_R_17
{
strings:
	$a0 = { 591b3e8b9611058db61101b9000231144646e2fa }


condition:
	$a0
}