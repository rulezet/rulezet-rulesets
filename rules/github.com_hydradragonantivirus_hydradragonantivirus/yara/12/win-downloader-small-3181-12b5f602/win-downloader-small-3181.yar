rule Win_Downloader_Small_3181
{
strings:
	$a0 = { 87b33569abed214a486701ed491227f457c7706b29133c13ae2de16748e7f7a973ee61b388ed70acbe1f72e6b7df76febded5753cb8abf6eb51e76e4a4ff54f6c76297fff300 }


condition:
	$a0
}