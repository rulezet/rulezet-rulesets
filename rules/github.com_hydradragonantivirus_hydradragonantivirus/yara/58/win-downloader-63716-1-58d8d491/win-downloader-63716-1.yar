rule Win_Downloader_63716_1
{
strings:
	$a0 = { 8bf68bc08bc08bf687f6505850b8521507645850b8581730585890559087ff8bec83ec34565e }


condition:
	$a0
}