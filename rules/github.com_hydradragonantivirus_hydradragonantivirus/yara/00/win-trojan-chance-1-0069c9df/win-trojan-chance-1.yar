rule Win_Trojan_Chance_1
{
strings:
	$a0 = { 33c08ed0bcfe7bfb8ec08ed8bbf003836f23028b4723b106d3e050be007c8ec033ffb90001fcf3 }


condition:
	$a0
}