rule Win_Trojan_Agent_32894
{
strings:
	$a0 = { af164bdb0eb99ceba3b59de38b723adf2b23648380ae31ad73e0d4c93e27d5e91e0166d13f9a6585a4fc06768a54fce68f550252fff3b9c887dc884feddef2390b027c7a4626d9685b989b163f48 }


condition:
	$a0
}