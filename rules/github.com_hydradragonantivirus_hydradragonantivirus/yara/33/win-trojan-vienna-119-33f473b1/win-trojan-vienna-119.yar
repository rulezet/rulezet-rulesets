rule Win_Trojan_Vienna_119
{
strings:
	$a0 = { 51b99004bab92cbfb82c8a058bdf4b8a272ae08827e2f79000fe02c4401d770608078c09bd0704c304058ff65a87ca0e }


condition:
	$a0
}