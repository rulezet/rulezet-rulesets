rule Win_Downloader_63431_1
{
strings:
	$a0 = { e8160993ede91608ccdecccccccc518d4c24042bc8 }

	$a1 = { 442050524956415445204b4559 }

	$a2 = { 5c7273615f7369676e2e63 }


condition:
	$a0 and $a1 and $a2
}