rule Win_Downloader_Banload_572
{
strings:
	$a0 = { 238b2eebff0f16d5772ba7d7af0057e7e7f2b7407e744190fc54cbd1f8ba85b71d25a1720e51c88260eda6c98e388ead80d0f17b33e97d94fc69524ce79aecc8 }


condition:
	$a0
}