rule Win_Trojan_Popwin_40
{
strings:
	$a0 = { baedf819bb117761aedf18b3b5e57d2bf122ddd2dffdebd8433091f9d7e7533db30eb8230fd140c9040557e20411563c87bf187a5d270e239434e80ab22a7a04 }


condition:
	$a0
}