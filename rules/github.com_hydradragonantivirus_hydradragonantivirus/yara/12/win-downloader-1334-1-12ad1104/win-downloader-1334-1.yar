rule Win_Downloader_1334_1
{
strings:
	$a0 = { 2522210c1208122121eb4b213deb213d4fe722221d1d54fefefefefefefefefe252221210f0ca51595331d2121e721213d4b214f3d544ffefefefefefefefefe }

	$a1 = { 33f2fefefefefefefefefefefefefe25cccccccc4141414141cccccccc485dd6f0fefefefefefefefefefefefefefe2541cc41cc41411d1d41 }

	$a2 = { 7a0075006c00750073 }


condition:
	$a0 and $a1 and $a2
}