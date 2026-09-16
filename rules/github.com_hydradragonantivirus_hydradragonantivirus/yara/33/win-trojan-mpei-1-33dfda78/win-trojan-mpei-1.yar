rule Win_Trojan_Mpei_1
{
strings:
	$a0 = { 619c81feecfd745883f901755381fa8000754d80fc03741f80fc0275432eff1e61009c5051b801 }


condition:
	$a0
}