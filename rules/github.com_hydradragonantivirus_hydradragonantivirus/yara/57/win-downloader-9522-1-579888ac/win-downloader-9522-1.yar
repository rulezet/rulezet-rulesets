rule Win_Downloader_9522_1
{
strings:
	$a0 = { 0fc813f51ae20fc1da21f9157d4cdf260fbcc8c1d61dbeedfccf56f7d181d68d }


condition:
	$a0
}