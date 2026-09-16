rule Win_Downloader_Swizzor_293
{
strings:
	$a0 = { 72edf4533ab7fc08a8b8c549810bd08119db302617b04ca25079022b3725da6afc1d720aa9db87ff78641ae8a9fa72d6 }


condition:
	$a0
}