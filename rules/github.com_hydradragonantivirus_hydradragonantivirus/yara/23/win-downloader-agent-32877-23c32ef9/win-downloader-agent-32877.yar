rule Win_Downloader_Agent_32877
{
strings:
	$a0 = { 92a12c325d2fea472feaea81ed96aeea5b0dc3b2655f6e3423f686528bac7c78da5d49634d0ea279ed62221571c9c129e8c8940b31e2f50d6d92b86d5368 }


condition:
	$a0
}