rule Win_Downloader_Banload_1080
{
strings:
	$a0 = { 08aaa34648ad4970464b19a93978047aff244d27348048dee93052477b80482cf7dcba9817de8a7af5f25b47e832262d136de5fc13ddd3e93201d4a74ddbd85f8c133acd }


condition:
	$a0
}