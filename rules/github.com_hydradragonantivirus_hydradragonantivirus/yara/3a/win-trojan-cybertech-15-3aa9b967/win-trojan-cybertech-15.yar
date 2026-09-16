rule Win_Trojan_CyberTech_15
{
strings:
	$a0 = { 5a59b80157cd21b43ecd21b8014359ba1efccd2156c3e900002a2e434f4d000d0a090952544c340d0a4a6f6f702076 }


condition:
	$a0
}