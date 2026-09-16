rule Win_Trojan_Flagyll_3
{
strings:
	$a0 = { 06e0018cc88ec0fab81c35cd218e1ee001891edb018c06dd01ba6101b81c25cd21fbcd201e }


condition:
	$a0
}