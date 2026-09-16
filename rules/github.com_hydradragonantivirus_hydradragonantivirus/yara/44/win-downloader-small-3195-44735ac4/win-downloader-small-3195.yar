rule Win_Downloader_Small_3195
{
strings:
	$a0 = { 673a9500c03be026d9253571465be13d3edcdfe04a3a15f684011c609efa1f7181cced73cbc52d77d3cf1f567eb978be43c7ec77c9d60d55dbb59096d281f252b0e7ec774a31 }


condition:
	$a0
}