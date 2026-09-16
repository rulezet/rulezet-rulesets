rule Win_Downloader_VB_407
{
strings:
	$a0 = { 930da6d5df9c4ebb01e57266da1f7a1d9d7a81c176e65fda38413612237263752adc6c76fc72e9a47cb88ec66d74d0660c0bfbd5dbeee32cb413f0df9e859e5c69 }


condition:
	$a0
}