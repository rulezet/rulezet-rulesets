rule Win_Trojan_Gobot_4
{
strings:
	$a0 = { 505fffd7a62ae4925b712cf3d33ea60c2be53fa4181b17a1001d17903a0da4fd1ce53f3619d61801199c501bd7 }


condition:
	$a0
}