rule Win_Downloader_Small_2483
{
strings:
	$a0 = { bf2c6040008db42454010000f3ab8dbc245401000083c9fff2aef7d149bf2c604000 }


condition:
	$a0
}