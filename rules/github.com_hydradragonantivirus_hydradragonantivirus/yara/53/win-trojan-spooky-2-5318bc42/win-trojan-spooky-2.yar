rule Win_Trojan_Spooky_2
{
strings:
	$a0 = { 020026c64504000e07b440ba0001b97400cd21b43ecd21b44febc4cd202a2e636f6d0054686973 }


condition:
	$a0
}