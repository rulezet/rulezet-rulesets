rule Win_Trojan_Surrender_2
{
strings:
	$a0 = { 720afe0dccb440f7d98bd7cc5a59b80157ccb43ecc591f }


condition:
	$a0
}