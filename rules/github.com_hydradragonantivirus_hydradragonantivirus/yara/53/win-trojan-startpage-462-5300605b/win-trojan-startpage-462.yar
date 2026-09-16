rule Win_Trojan_Startpage_462
{
strings:
	$a0 = { fc7572e7e46e7363653c6368f73e8a2f0a6d5ec93fefd269c3d2916d79d46f63382671fac6d86c69ba152532304b733863792a4f123f2047 }


condition:
	$a0
}