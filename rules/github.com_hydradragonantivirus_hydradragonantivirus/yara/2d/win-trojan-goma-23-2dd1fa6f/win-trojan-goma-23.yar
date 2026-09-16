rule Win_Trojan_Goma_23
{
strings:
	$a0 = { 0400052a2e4558450a476f6d612e484c4c50209a00007c009ace004c005589e5b800019acd02 }


condition:
	$a0
}