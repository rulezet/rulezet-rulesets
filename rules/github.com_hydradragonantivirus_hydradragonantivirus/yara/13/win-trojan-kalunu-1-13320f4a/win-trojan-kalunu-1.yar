rule Win_Trojan_Kalunu_1
{
strings:
	$a0 = { 2e5441560090cfe8e800b44fe917fde8a1fce887fcb915058d960001b440cd21e879fce88dfc }


condition:
	$a0
}