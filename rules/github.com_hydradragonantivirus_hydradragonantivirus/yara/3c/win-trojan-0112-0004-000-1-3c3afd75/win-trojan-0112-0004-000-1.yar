rule Win_Trojan__0112_0004_000_1
{
strings:
	$a0 = { 51b90300b440ba1e04cd21b44059ba3a04cd2132c0e83100ba1b04cd215a5980e1e080c900b801 }


condition:
	$a0
}