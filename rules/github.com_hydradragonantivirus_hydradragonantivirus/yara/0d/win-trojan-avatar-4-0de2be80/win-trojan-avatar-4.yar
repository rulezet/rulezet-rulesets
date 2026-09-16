rule Win_Trojan_Avatar_4
{
strings:
	$a0 = { 15337572f9d4ff8ac4b40bbb0dd0cd210bdb74681e8cd8488ed82bff803d5a755b836d032790836d1227908e45 }


condition:
	$a0
}