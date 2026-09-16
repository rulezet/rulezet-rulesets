rule Win_Trojan_SillyC_90
{
strings:
	$a0 = { 03d789550c5acd2132c0e80c008bd7cd21b43ecd21b44febc6b4429933c9cd2192b440b160 }


condition:
	$a0
}