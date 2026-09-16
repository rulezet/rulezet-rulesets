rule Win_Downloader_63717_1
{
strings:
	$a0 = { 3e206e756c00004f70656e000000002f632064656c }

	$a1 = { 434f4d535045430077676574 }

	$a2 = { 73797979256c752e657865 }


condition:
	$a0 and $a1 and $a2
}