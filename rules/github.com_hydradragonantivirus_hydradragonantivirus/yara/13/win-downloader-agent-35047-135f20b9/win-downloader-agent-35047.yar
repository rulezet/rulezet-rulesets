rule Win_Downloader_Agent_35047
{
strings:
	$a0 = { 59f3774a1669804d3c183f412031e3db8482647b117e327fb42077bdd9ffbe2b3ed377ff234804293828314d18451cd835ab }


condition:
	$a0
}